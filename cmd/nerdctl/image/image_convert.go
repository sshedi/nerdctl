/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package image

import (
	"compress/gzip"

	"github.com/spf13/cobra"

	"github.com/containerd/nerdctl/v2/cmd/nerdctl/completion"
	"github.com/containerd/nerdctl/v2/cmd/nerdctl/helpers"
	"github.com/containerd/nerdctl/v2/pkg/api/types"
	"github.com/containerd/nerdctl/v2/pkg/clientutil"
	"github.com/containerd/nerdctl/v2/pkg/cmd/image"
)

const imageConvertHelp = `Convert an image format.

e.g., 'nerdctl image convert --estargz --oci example.com/foo:orig example.com/foo:esgz'

Use '--platform' to define the output platform.
When '--all-platforms' is given all images in a manifest list must be available.

For encryption and decryption, use 'nerdctl image (encrypt|decrypt)' command.
`

// imageConvertCommand is from https://github.com/containerd/stargz-snapshotter/blob/d58f43a8235e46da73fb94a1a35280cb4d607b2c/cmd/ctr-remote/commands/convert.go
func convertCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "convert [flags] <source_ref> <target_ref>...",
		Short:             "convert an image",
		Long:              imageConvertHelp,
		Args:              cobra.MinimumNArgs(2),
		RunE:              imageConvertAction,
		ValidArgsFunction: imageConvertShellComplete,
		SilenceUsage:      true,
		SilenceErrors:     true,
	}

	cmd.Flags().String("format", "", "Format the output using the given Go template, e.g, 'json'")

	// #region estargz flags
	cmd.Flags().Bool("estargz", false, "Convert legacy tar(.gz) layers to eStargz for lazy pulling. Should be used in conjunction with '--oci'")
	cmd.Flags().String("estargz-record-in", "", "Read 'ctr-remote optimize --record-out=<FILE>' record file (EXPERIMENTAL)")
	cmd.Flags().Int("estargz-compression-level", gzip.BestCompression, "eStargz compression level")
	cmd.Flags().Int("estargz-chunk-size", 0, "eStargz chunk size")
	cmd.Flags().Int("estargz-min-chunk-size", 0, "The minimal number of bytes of data must be written in one gzip stream. (requires stargz-snapshotter >= v0.13.0)")
	cmd.Flags().Bool("estargz-external-toc", false, "Separate TOC JSON into another image (called \"TOC image\"). The name of TOC image is the original + \"-esgztoc\" suffix. Both eStargz and the TOC image should be pushed to the same registry. (requires stargz-snapshotter >= v0.13.0) (EXPERIMENTAL)")
	cmd.Flags().Bool("estargz-keep-diff-id", false, "Convert to esgz without changing diffID (cannot be used in conjunction with '--estargz-record-in'. must be specified with '--estargz-external-toc')")
	// #endregion

	// #region zstd flags
	cmd.Flags().Bool("zstd", false, "Convert legacy tar(.gz) layers to zstd. Should be used in conjunction with '--oci'")
	cmd.Flags().Int("zstd-compression-level", 3, "zstd compression level")
	// #endregion

	// #region zstd:chunked flags
	cmd.Flags().Bool("zstdchunked", false, "Convert legacy tar(.gz) layers to zstd:chunked for lazy pulling. Should be used in conjunction with '--oci'")
	cmd.Flags().String("zstdchunked-record-in", "", "Read 'ctr-remote optimize --record-out=<FILE>' record file (EXPERIMENTAL)")
	cmd.Flags().Int("zstdchunked-compression-level", 3, "zstd:chunked compression level") // SpeedDefault; see also https://pkg.go.dev/github.com/klauspost/compress/zstd#EncoderLevel
	cmd.Flags().Int("zstdchunked-chunk-size", 0, "zstd:chunked chunk size")
	// #endregion

	// #region nydus flags
	cmd.Flags().Bool("nydus", false, "Convert an OCI image to Nydus image. Should be used in conjunction with '--oci'")
	cmd.Flags().String("nydus-builder-path", "nydus-image", "The nydus-image binary path, if unset, search in PATH environment")
	cmd.Flags().String("nydus-work-dir", "", "Work directory path for image conversion, default is the nerdctl data root directory")
	cmd.Flags().String("nydus-prefetch-patterns", "", "The file path pattern list want to prefetch")
	cmd.Flags().String("nydus-compressor", "lz4_block", "Nydus blob compression algorithm, possible values: `none`, `lz4_block`, `zstd`, default is `lz4_block`")
	// #endregion

	// #region overlaybd flags
	cmd.Flags().Bool("overlaybd", false, "Convert tar.gz layers to overlaybd layers")
	cmd.Flags().String("overlaybd-fs-type", "ext4", "Filesystem type for overlaybd")
	cmd.Flags().String("overlaybd-dbstr", "", "Database config string for overlaybd")
	// #endregion

	// #region soci flags
	cmd.Flags().Bool("soci", false, "Convert image to SOCI Index V2 format.")
	cmd.Flags().Int64("soci-min-layer-size", -1, "The minimum size of layers that will be converted to SOCI Index V2 format")
	cmd.Flags().Int64("soci-span-size", -1, "The size of SOCI spans")
	// #endregion

	// #region generic flags
	cmd.Flags().Bool("uncompress", false, "Convert tar.gz layers to uncompressed tar layers")
	cmd.Flags().Bool("oci", false, "Convert Docker media types to OCI media types")
	// #endregion

	// #region platform flags
	// platform is defined as StringSlice, not StringArray, to allow specifying "--platform=amd64,arm64"
	cmd.Flags().StringSlice("platform", []string{}, "Convert content for a specific platform")
	cmd.RegisterFlagCompletionFunc("platform", completion.Platforms)
	cmd.Flags().Bool("all-platforms", false, "Convert content for all platforms")
	// #endregion

	return cmd
}

func convertOptions(cmd *cobra.Command) (types.ImageConvertOptions, error) {
	globalOptions, err := helpers.ProcessRootCmdFlags(cmd)
	if err != nil {
		return types.ImageConvertOptions{}, err
	}
	format, err := cmd.Flags().GetString("format")
	if err != nil {
		return types.ImageConvertOptions{}, err
	}

	// #region estargz flags
	estargz, err := cmd.Flags().GetBool("estargz")
	if err != nil {
		return types.ImageConvertOptions{}, err
	}
	estargzRecordIn, err := cmd.Flags().GetString("estargz-record-in")
	if err != nil {
		return types.ImageConvertOptions{}, err
	}
	estargzCompressionLevel, err := cmd.Flags().GetInt("estargz-compression-level")
	if err != nil {
		return types.ImageConvertOptions{}, err
	}
	estargzChunkSize, err := cmd.Flags().GetInt("estargz-chunk-size")
	if err != nil {
		return types.ImageConvertOptions{}, err
	}
	estargzMinChunkSize, err := cmd.Flags().GetInt("estargz-min-chunk-size")
	if err != nil {
		return types.ImageConvertOptions{}, err
	}
	estargzExternalTOC, err := cmd.Flags().GetBool("estargz-external-toc")
	if err != nil {
		return types.ImageConvertOptions{}, err
	}
	estargzKeepDiffID, err := cmd.Flags().GetBool("estargz-keep-diff-id")
	if err != nil {
		return types.ImageConvertOptions{}, err
	}
	// #endregion

	// #region zstd flags
	zstd, err := cmd.Flags().GetBool("zstd")
	if err != nil {
		return types.ImageConvertOptions{}, err
	}
	zstdCompressionLevel, err := cmd.Flags().GetInt("zstd-compression-level")
	if err != nil {
		return types.ImageConvertOptions{}, err
	}
	// #endregion

	// #region zstd:chunked flags
	zstdchunked, err := cmd.Flags().GetBool("zstdchunked")
	if err != nil {
		return types.ImageConvertOptions{}, err
	}
	zstdChunkedCompressionLevel, err := cmd.Flags().GetInt("zstdchunked-compression-level")
	if err != nil {
		return types.ImageConvertOptions{}, err
	}
	zstdChunkedChunkSize, err := cmd.Flags().GetInt("zstdchunked-chunk-size")
	if err != nil {
		return types.ImageConvertOptions{}, err
	}
	zstdChunkedRecordIn, err := cmd.Flags().GetString("zstdchunked-record-in")
	if err != nil {
		return types.ImageConvertOptions{}, err
	}
	// #endregion

	// #region nydus flags
	nydus, err := cmd.Flags().GetBool("nydus")
	if err != nil {
		return types.ImageConvertOptions{}, err
	}
	nydusBuilderPath, err := cmd.Flags().GetString("nydus-builder-path")
	if err != nil {
		return types.ImageConvertOptions{}, err
	}
	nydusWorkDir, err := cmd.Flags().GetString("nydus-work-dir")
	if err != nil {
		return types.ImageConvertOptions{}, err
	}
	nydusPrefetchPatterns, err := cmd.Flags().GetString("nydus-prefetch-patterns")
	if err != nil {
		return types.ImageConvertOptions{}, err
	}
	nydusCompressor, err := cmd.Flags().GetString("nydus-compressor")
	if err != nil {
		return types.ImageConvertOptions{}, err
	}
	// #endregion

	// #region overlaybd flags
	overlaybd, err := cmd.Flags().GetBool("overlaybd")
	if err != nil {
		return types.ImageConvertOptions{}, err
	}
	overlaybdFsType, err := cmd.Flags().GetString("overlaybd-fs-type")
	if err != nil {
		return types.ImageConvertOptions{}, err
	}
	overlaybdDbstr, err := cmd.Flags().GetString("overlaybd-dbstr")
	if err != nil {
		return types.ImageConvertOptions{}, err
	}
	// #endregion

	// #region soci flags
	soci, err := cmd.Flags().GetBool("soci")
	if err != nil {
		return types.ImageConvertOptions{}, err
	}
	sociMinLayerSize, err := cmd.Flags().GetInt64("soci-min-layer-size")
	if err != nil {
		return types.ImageConvertOptions{}, err
	}
	sociSpanSize, err := cmd.Flags().GetInt64("soci-span-size")
	if err != nil {
		return types.ImageConvertOptions{}, err
	}
	// #endregion

	// #region generic flags
	uncompress, err := cmd.Flags().GetBool("uncompress")
	if err != nil {
		return types.ImageConvertOptions{}, err
	}
	oci, err := cmd.Flags().GetBool("oci")
	if err != nil {
		return types.ImageConvertOptions{}, err
	}
	// #endregion

	// #region platform flags
	platforms, err := cmd.Flags().GetStringSlice("platform")
	if err != nil {
		return types.ImageConvertOptions{}, err
	}
	allPlatforms, err := cmd.Flags().GetBool("all-platforms")
	if err != nil {
		return types.ImageConvertOptions{}, err
	}
	// #endregion
	return types.ImageConvertOptions{
		GOptions: globalOptions,
		Format:   format,
		// #region generic flags
		Uncompress: uncompress,
		Oci:        oci,
		// #endregion
		// #region platform flags
		Platforms:    platforms,
		AllPlatforms: allPlatforms,
		// #endregion
		// Embed image format options
		EstargzOptions: types.EstargzOptions{
			Estargz:                 estargz,
			EstargzRecordIn:         estargzRecordIn,
			EstargzCompressionLevel: estargzCompressionLevel,
			EstargzChunkSize:        estargzChunkSize,
			EstargzMinChunkSize:     estargzMinChunkSize,
			EstargzExternalToc:      estargzExternalTOC,
			EstargzKeepDiffID:       estargzKeepDiffID,
		},
		ZstdOptions: types.ZstdOptions{
			Zstd:                 zstd,
			ZstdCompressionLevel: zstdCompressionLevel,
		},
		ZstdChunkedOptions: types.ZstdChunkedOptions{
			ZstdChunked:                 zstdchunked,
			ZstdChunkedCompressionLevel: zstdChunkedCompressionLevel,
			ZstdChunkedChunkSize:        zstdChunkedChunkSize,
			ZstdChunkedRecordIn:         zstdChunkedRecordIn,
		},
		NydusOptions: types.NydusOptions{
			Nydus:                 nydus,
			NydusBuilderPath:      nydusBuilderPath,
			NydusWorkDir:          nydusWorkDir,
			NydusPrefetchPatterns: nydusPrefetchPatterns,
			NydusCompressor:       nydusCompressor,
		},
		OverlaybdOptions: types.OverlaybdOptions{
			Overlaybd:      overlaybd,
			OverlayFsType:  overlaybdFsType,
			OverlaydbDBStr: overlaybdDbstr,
		},
		SociConvertOptions: types.SociConvertOptions{
			Soci: soci,
			SociOptions: types.SociOptions{
				SpanSize:     sociSpanSize,
				MinLayerSize: sociMinLayerSize,
			},
		},
		Stdout: cmd.OutOrStdout(),
	}, nil
}

func imageConvertAction(cmd *cobra.Command, args []string) error {
	options, err := convertOptions(cmd)
	if err != nil {
		return err
	}
	srcRawRef := args[0]
	destRawRef := args[1]

	client, ctx, cancel, err := clientutil.NewClient(cmd.Context(), options.GOptions.Namespace, options.GOptions.Address)
	if err != nil {
		return err
	}
	defer cancel()

	return image.Convert(ctx, client, srcRawRef, destRawRef, options)
}

func imageConvertShellComplete(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	// show image names
	return completion.ImageNames(cmd)
}
