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

package container

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	mobymount "github.com/moby/sys/mount"
	"gotest.tools/v3/assert"

	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/nerdctl/mod/tigron/expect"
	"github.com/containerd/nerdctl/mod/tigron/test"
	"github.com/containerd/nerdctl/mod/tigron/tig"

	"github.com/containerd/nerdctl/v2/cmd/nerdctl/helpers"
	"github.com/containerd/nerdctl/v2/pkg/rootlessutil"
	"github.com/containerd/nerdctl/v2/pkg/testutil"
	"github.com/containerd/nerdctl/v2/pkg/testutil/nerdtest"
)

func TestRunVolume(t *testing.T) {
	t.Parallel()
	base := testutil.NewBase(t)
	tID := testutil.Identifier(t)
	rwDir, err := os.MkdirTemp(t.TempDir(), "rw")
	if err != nil {
		t.Fatal(err)
	}
	roDir, err := os.MkdirTemp(t.TempDir(), "ro")
	if err != nil {
		t.Fatal(err)
	}
	rwVolName := tID + "-rw"
	roVolName := tID + "-ro"
	for _, v := range []string{rwVolName, roVolName} {
		defer base.Cmd("volume", "rm", "-f", v).Run()
		base.Cmd("volume", "create", v).AssertOK()
	}

	containerName := tID
	defer base.Cmd("rm", "-f", containerName).AssertOK()
	base.Cmd("run",
		"-d",
		"--name", containerName,
		"-v", fmt.Sprintf("%s:/mnt1", rwDir),
		"-v", fmt.Sprintf("%s:/mnt2:ro", roDir),
		"-v", fmt.Sprintf("%s:/mnt3", rwVolName),
		"-v", fmt.Sprintf("%s:/mnt4:ro", roVolName),
		testutil.AlpineImage,
		"top",
	).AssertOK()
	base.Cmd("exec", containerName, "sh", "-exc", "echo -n str1 > /mnt1/file1").AssertOK()
	base.Cmd("exec", containerName, "sh", "-exc", "echo -n str2 > /mnt2/file2").AssertFail()
	base.Cmd("exec", containerName, "sh", "-exc", "echo -n str3 > /mnt3/file3").AssertOK()
	base.Cmd("exec", containerName, "sh", "-exc", "echo -n str4 > /mnt4/file4").AssertFail()
	base.Cmd("rm", "-f", containerName).AssertOK()
	base.Cmd("run",
		"--rm",
		"-v", fmt.Sprintf("%s:/mnt1", rwDir),
		"-v", fmt.Sprintf("%s:/mnt3", rwVolName),
		testutil.AlpineImage,
		"cat", "/mnt1/file1", "/mnt3/file3",
	).AssertOutExactly("str1str3")
	base.Cmd("run",
		"--rm",
		"-v", fmt.Sprintf("%s:/mnt3/mnt1", rwDir),
		"-v", fmt.Sprintf("%s:/mnt3", rwVolName),
		testutil.AlpineImage,
		"cat", "/mnt3/mnt1/file1", "/mnt3/file3",
	).AssertOutExactly("str1str3")
}

func TestRunAnonymousVolume(t *testing.T) {
	t.Parallel()
	base := testutil.NewBase(t)
	base.Cmd("run", "--rm", "-v", "/foo", testutil.AlpineImage).AssertOK()
	base.Cmd("run", "--rm", "-v", "TestVolume2:/foo", testutil.AlpineImage).AssertOK()
	base.Cmd("run", "--rm", "-v", "TestVolume", testutil.AlpineImage).AssertOK()

	// Destination must be an absolute path not named volume
	base.Cmd("run", "--rm", "-v", "TestVolume2:TestVolumes", testutil.AlpineImage).AssertFail()
}

func TestRunVolumeRelativePath(t *testing.T) {
	t.Parallel()
	base := testutil.NewBase(t)
	base.Dir = t.TempDir()
	base.Cmd("run", "--rm", "-v", "./foo:/mnt/foo", testutil.AlpineImage).AssertOK()
	base.Cmd("run", "--rm", "-v", "./foo", testutil.AlpineImage).AssertOK()

	// Destination must be an absolute path not a relative path
	base.Cmd("run", "--rm", "-v", "./foo:./foo", testutil.AlpineImage).AssertFail()
}

func TestRunAnonymousVolumeWithTypeMountFlag(t *testing.T) {
	t.Parallel()
	base := testutil.NewBase(t)
	base.Cmd("run", "--rm", "--mount", "type=volume,dst=/foo", testutil.AlpineImage,
		"mountpoint", "-q", "/foo").AssertOK()
}

func TestRunAnonymousVolumeWithBuild(t *testing.T) {
	t.Parallel()
	testutil.RequiresBuild(t)
	testutil.RegisterBuildCacheCleanup(t)
	base := testutil.NewBase(t)
	imageName := testutil.Identifier(t)
	defer base.Cmd("rmi", imageName).Run()

	dockerfile := fmt.Sprintf(`FROM %s
VOLUME /foo
        `, testutil.AlpineImage)

	buildCtx := helpers.CreateBuildContext(t, dockerfile)

	base.Cmd("build", "-t", imageName, buildCtx).AssertOK()
	base.Cmd("run", "--rm", "-v", "/foo", testutil.AlpineImage,
		"mountpoint", "-q", "/foo").AssertOK()
}

func TestRunCopyingUpInitialContentsOnVolume(t *testing.T) {
	t.Parallel()
	testutil.RequiresBuild(t)
	testutil.RegisterBuildCacheCleanup(t)
	base := testutil.NewBase(t)
	imageName := testutil.Identifier(t)
	defer base.Cmd("rmi", imageName).Run()
	volName := testutil.Identifier(t) + "-vol"
	defer base.Cmd("volume", "rm", volName).Run()

	dockerfile := fmt.Sprintf(`FROM %s
RUN mkdir -p /mnt && echo hi > /mnt/initial_file
CMD ["cat", "/mnt/initial_file"]
        `, testutil.AlpineImage)

	buildCtx := helpers.CreateBuildContext(t, dockerfile)

	base.Cmd("build", "-t", imageName, buildCtx).AssertOK()

	//AnonymousVolume
	base.Cmd("run", "--rm", imageName).AssertOutExactly("hi\n")
	base.Cmd("run", "-v", "/mnt", "--rm", imageName).AssertOutExactly("hi\n")

	//NamedVolume should be automatically created
	base.Cmd("run", "-v", volName+":/mnt", "--rm", imageName).AssertOutExactly("hi\n")
}

func TestRunCopyingUpInitialContentsOnDockerfileVolume(t *testing.T) {
	t.Parallel()
	testutil.RequiresBuild(t)
	testutil.RegisterBuildCacheCleanup(t)
	base := testutil.NewBase(t)
	imageName := testutil.Identifier(t)
	defer base.Cmd("rmi", imageName).Run()
	volName := testutil.Identifier(t) + "-vol"
	defer base.Cmd("volume", "rm", volName).Run()

	dockerfile := fmt.Sprintf(`FROM %s
RUN mkdir -p /mnt && echo hi > /mnt/initial_file
VOLUME /mnt
CMD ["cat", "/mnt/initial_file"]
        `, testutil.AlpineImage)

	buildCtx := helpers.CreateBuildContext(t, dockerfile)

	base.Cmd("build", "-t", imageName, buildCtx).AssertOK()
	//AnonymousVolume
	base.Cmd("run", "--rm", imageName).AssertOutExactly("hi\n")
	base.Cmd("run", "-v", "/mnt", "--rm", imageName).AssertOutExactly("hi\n")

	//NamedVolume
	base.Cmd("volume", "create", volName).AssertOK()
	base.Cmd("run", "-v", volName+":/mnt", "--rm", imageName).AssertOutExactly("hi\n")

	//mount bind
	tmpDir, err := os.MkdirTemp(t.TempDir(), "hostDir")
	assert.NilError(t, err)

	base.Cmd("run", "-v", fmt.Sprintf("%s:/mnt", tmpDir), "--rm", imageName).AssertFail()
}

func TestRunCopyingUpInitialContentsOnVolumeShouldRetainSymlink(t *testing.T) {
	t.Parallel()
	testutil.RequiresBuild(t)
	testutil.RegisterBuildCacheCleanup(t)
	base := testutil.NewBase(t)
	imageName := testutil.Identifier(t)
	defer base.Cmd("rmi", imageName).Run()

	dockerfile := fmt.Sprintf(`FROM %s
RUN ln -s ../../../../../../../../../../../../../../../../../../etc/passwd /mnt/passwd
VOLUME /mnt
CMD ["readlink", "/mnt/passwd"]
        `, testutil.AlpineImage)
	const expected = "../../../../../../../../../../../../../../../../../../etc/passwd\n"

	buildCtx := helpers.CreateBuildContext(t, dockerfile)

	base.Cmd("build", "-t", imageName, buildCtx).AssertOK()

	base.Cmd("run", "--rm", imageName).AssertOutExactly(expected)
	base.Cmd("run", "-v", "/mnt", "--rm", imageName).AssertOutExactly(expected)
}

func TestRunCopyingUpInitialContentsShouldNotResetTheCopiedContents(t *testing.T) {
	t.Parallel()
	testutil.RequiresBuild(t)
	testutil.RegisterBuildCacheCleanup(t)
	base := testutil.NewBase(t)
	tID := testutil.Identifier(t)
	imageName := tID + "-img"
	volumeName := tID + "-vol"
	containerName := tID
	defer func() {
		base.Cmd("rm", "-f", containerName).Run()
		base.Cmd("volume", "rm", volumeName).Run()
		base.Cmd("rmi", imageName).Run()
	}()

	dockerfile := fmt.Sprintf(`FROM %s
RUN echo -n "rev0" > /mnt/file
`, testutil.AlpineImage)

	buildCtx := helpers.CreateBuildContext(t, dockerfile)

	base.Cmd("build", "-t", imageName, buildCtx).AssertOK()

	base.Cmd("volume", "create", volumeName)
	runContainer := func() {
		base.Cmd("run", "-d", "--name", containerName, "-v", volumeName+":/mnt", imageName, "sleep", nerdtest.Infinity).AssertOK()
	}
	runContainer()
	base.EnsureContainerStarted(containerName)
	base.Cmd("exec", containerName, "cat", "/mnt/file").AssertOutExactly("rev0")
	base.Cmd("exec", containerName, "sh", "-euc", "echo -n \"rev1\" >/mnt/file").AssertOK()
	base.Cmd("rm", "-f", containerName).AssertOK()
	runContainer()
	base.EnsureContainerStarted(containerName)
	base.Cmd("exec", containerName, "cat", "/mnt/file").AssertOutExactly("rev1")
}

func TestRunTmpfs(t *testing.T) {
	t.Parallel()
	base := testutil.NewBase(t)
	f := func(allow, deny []string) func(stdout string) error {
		return func(stdout string) error {
			lines := strings.Split(strings.TrimSpace(stdout), "\n")
			if len(lines) != 1 {
				return fmt.Errorf("expected 1 lines, got %q", stdout)
			}
			for _, s := range allow {
				if !strings.Contains(stdout, s) {
					return fmt.Errorf("expected stdout to contain %q, got %q", s, stdout)
				}
			}
			for _, s := range deny {
				if strings.Contains(stdout, s) {
					return fmt.Errorf("expected stdout not to contain %q, got %q", s, stdout)
				}
			}
			return nil
		}
	}
	base.Cmd("run", "--rm", "--tmpfs", "/tmp", testutil.AlpineImage, "grep", "/tmp", "/proc/mounts").AssertOutWithFunc(f([]string{"rw", "nosuid", "nodev", "noexec"}, nil))
	base.Cmd("run", "--rm", "--tmpfs", "/tmp:size=64m,exec", testutil.AlpineImage, "grep", "/tmp", "/proc/mounts").AssertOutWithFunc(f([]string{"rw", "nosuid", "nodev", "size=65536k"}, []string{"noexec"}))
	// for https://github.com/containerd/nerdctl/issues/594
	base.Cmd("run", "--rm", "--tmpfs", "/dev/shm:rw,exec,size=1g", testutil.AlpineImage, "grep", "/dev/shm", "/proc/mounts").AssertOutWithFunc(f([]string{"rw", "nosuid", "nodev", "size=1048576k"}, []string{"noexec"}))
}

func TestRunBindMountTmpfs(t *testing.T) {
	t.Parallel()
	base := testutil.NewBase(t)
	f := func(allow []string) func(stdout string) error {
		return func(stdout string) error {
			lines := strings.Split(strings.TrimSpace(stdout), "\n")
			if len(lines) != 1 {
				return fmt.Errorf("expected 1 lines, got %q", stdout)
			}
			for _, s := range allow {
				if !strings.Contains(stdout, s) {
					return fmt.Errorf("expected stdout to contain %q, got %q", s, stdout)
				}
			}
			return nil
		}
	}
	base.Cmd("run", "--rm", "--mount", "type=tmpfs,target=/tmp", testutil.AlpineImage, "grep", "/tmp", "/proc/mounts").AssertOutWithFunc(f([]string{"rw", "nosuid", "nodev", "noexec"}))
	base.Cmd("run", "--rm", "--mount", "type=tmpfs,target=/tmp,tmpfs-size=64m", testutil.AlpineImage, "grep", "/tmp", "/proc/mounts").AssertOutWithFunc(f([]string{"rw", "nosuid", "nodev", "size=65536k"}))
}

func mountExistsWithOpt(mountPoint, mountOpt string) test.Comparator {
	return func(stdout string, t tig.T) {
		lines := strings.Split(strings.TrimSpace(stdout), "\n")
		mountOutput := []string{}
		for _, line := range lines {
			if strings.Contains(line, mountPoint) {
				mountOutput = strings.Split(line, " ")
				break
			}
		}

		assert.Assert(t, len(mountOutput) > 0, "we should have found the mount point in /proc/mounts")
		assert.Assert(t, len(mountOutput) >= 4, "invalid format for mount line")

		options := strings.Split(mountOutput[3], ",")

		found := false
		for _, opt := range options {
			if mountOpt == opt {
				found = true
				break
			}
		}

		assert.Assert(t, found, "mount option %s not found", mountOpt)
	}
}

func TestRunBindMountBind(t *testing.T) {
	testCase := nerdtest.Setup()

	testCase.Setup = func(data test.Data, helpers test.Helpers) {
		// Run a container with bind mount directories, one rw, the other ro
		rwDir := data.Temp().Dir("rw")
		roDir := data.Temp().Dir("ro")

		helpers.Ensure(
			"run",
			"-d",
			"--name", data.Identifier("container"),
			"--mount", fmt.Sprintf("type=bind,src=%s,target=/mntrw", rwDir),
			"--mount", fmt.Sprintf("type=bind,src=%s,target=/mntro,ro", roDir),
			testutil.AlpineImage,
			"top",
		)

		nerdtest.EnsureContainerStarted(helpers, data.Identifier("container"))

		// Save host rwDir location and container id for subtests
		data.Labels().Set("container", data.Identifier("container"))
		data.Labels().Set("rwDir", rwDir)
	}

	testCase.SubTests = []*test.Case{
		{
			Description: "ensure we cannot write to ro mount",
			Command: func(data test.Data, helpers test.Helpers) test.TestableCommand {
				return helpers.Command("exec", data.Labels().Get("container"), "sh", "-exc", "echo -n failure > /mntro/file")
			},
			Expected: test.Expects(expect.ExitCodeGenericFail, nil, nil),
		},
		{
			Description: "ensure we can write to rw, and read it back from another container mounting the same target",
			Setup: func(data test.Data, helpers test.Helpers) {
				helpers.Ensure("exec", data.Labels().Get("container"), "sh", "-exc", "echo -n success > /mntrw/file")
			},
			Command: func(data test.Data, helpers test.Helpers) test.TestableCommand {
				return helpers.Command(
					"run",
					"--rm",
					"--mount", fmt.Sprintf("type=bind,src=%s,target=/mntrw", data.Labels().Get("rwDir")),
					testutil.AlpineImage,
					"cat", "/mntrw/file",
				)
			},
			Expected: test.Expects(expect.ExitCodeSuccess, nil, expect.Equals("success")),
		},
		{
			Description: "Check that mntrw is seen in /proc/mounts",
			Command: func(data test.Data, helpers test.Helpers) test.TestableCommand {
				return helpers.Command("exec", data.Labels().Get("container"), "cat", "/proc/mounts")
			},
			Expected: func(data test.Data, helpers test.Helpers) *test.Expected {
				return &test.Expected{
					Output: expect.All(
						// Ensure we have mntrw in the mount list
						mountExistsWithOpt("/mntrw", "rw"),
						mountExistsWithOpt("/mntro", "ro"),
					),
				}
			},
		},
	}

	testCase.Cleanup = func(data test.Data, helpers test.Helpers) {
		helpers.Anyhow("rm", "-f", data.Identifier("container"))
	}

	testCase.Run(t)
}

func TestRunMountBindMode(t *testing.T) {
	if rootlessutil.IsRootless() {
		t.Skip("must be superuser to use mount")
	}
	t.Parallel()
	base := testutil.NewBase(t)

	tmpDir1, err := os.MkdirTemp(t.TempDir(), "rw")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir1)
	tmpDir1Mnt := filepath.Join(tmpDir1, "mnt")
	if err := os.MkdirAll(tmpDir1Mnt, 0700); err != nil {
		t.Fatal(err)
	}

	tmpDir2, err := os.MkdirTemp(t.TempDir(), "ro")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir2)

	if err := mobymount.Mount(tmpDir2, tmpDir1Mnt, "none", "bind,ro"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := mobymount.Unmount(tmpDir1Mnt); err != nil {
			t.Fatal(err)
		}
	}()

	base.Cmd("run",
		"--rm",
		"--mount", fmt.Sprintf("type=bind,bind-nonrecursive,src=%s,target=/mnt1", tmpDir1),
		testutil.AlpineImage,
		"sh", "-euxc", "apk add findmnt -q && findmnt -nR /mnt1",
	).AssertOutWithFunc(func(stdout string) error {
		lines := strings.Split(strings.TrimSpace(stdout), "\n")
		if len(lines) != 1 {
			return fmt.Errorf("expected 1 line, got %q", stdout)
		}
		if !strings.HasPrefix(lines[0], "/mnt1") {
			return fmt.Errorf("expected mount /mnt1, got %q", lines[0])
		}
		return nil
	})

	base.Cmd("run",
		"--rm",
		"--mount", fmt.Sprintf("type=bind,bind-nonrecursive=false,src=%s,target=/mnt1", tmpDir1),
		testutil.AlpineImage,
		"sh", "-euxc", "apk add findmnt -q && findmnt -nR /mnt1",
	).AssertOutWithFunc(func(stdout string) error {
		lines := strings.Split(strings.TrimSpace(stdout), "\n")
		if len(lines) != 2 {
			return fmt.Errorf("expected 2 line, got %q", stdout)
		}
		if !strings.HasPrefix(lines[0], "/mnt1") {
			return fmt.Errorf("expected mount /mnt1, got %q", lines[0])
		}
		return nil
	})
}

func TestRunVolumeBindMode(t *testing.T) {
	if rootlessutil.IsRootless() {
		t.Skip("must be superuser to use mount")
	}
	testutil.DockerIncompatible(t)
	t.Parallel()
	base := testutil.NewBase(t)

	tmpDir1, err := os.MkdirTemp(t.TempDir(), "rw")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir1)
	tmpDir1Mnt := filepath.Join(tmpDir1, "mnt")
	if err := os.MkdirAll(tmpDir1Mnt, 0700); err != nil {
		t.Fatal(err)
	}

	tmpDir2, err := os.MkdirTemp(t.TempDir(), "ro")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir2)

	if err := mobymount.Mount(tmpDir2, tmpDir1Mnt, "none", "bind,ro"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := mobymount.Unmount(tmpDir1Mnt); err != nil {
			t.Fatal(err)
		}
	}()

	base.Cmd("run",
		"--rm",
		"-v", fmt.Sprintf("%s:/mnt1:bind", tmpDir1),
		testutil.AlpineImage,
		"sh", "-euxc", "apk add findmnt -q && findmnt -nR /mnt1",
	).AssertOutWithFunc(func(stdout string) error {
		lines := strings.Split(strings.TrimSpace(stdout), "\n")
		if len(lines) != 1 {
			return fmt.Errorf("expected 1 line, got %q", stdout)
		}
		if !strings.HasPrefix(lines[0], "/mnt1") {
			return fmt.Errorf("expected mount /mnt1, got %q", lines[0])
		}
		return nil
	})

	base.Cmd("run",
		"--rm",
		"-v", fmt.Sprintf("%s:/mnt1:rbind", tmpDir1),
		testutil.AlpineImage,
		"sh", "-euxc", "apk add findmnt -q && findmnt -nR /mnt1",
	).AssertOutWithFunc(func(stdout string) error {
		lines := strings.Split(strings.TrimSpace(stdout), "\n")
		if len(lines) != 2 {
			return fmt.Errorf("expected 2 line, got %q", stdout)
		}
		if !strings.HasPrefix(lines[0], "/mnt1") {
			return fmt.Errorf("expected mount /mnt1, got %q", lines[0])
		}
		return nil
	})
}

func TestRunBindMountPropagation(t *testing.T) {
	t.Skip("This test is currently broken. See https://github.com/containerd/nerdctl/issues/3404")

	tID := testutil.Identifier(t)

	if !isRootfsShareableMount() {
		t.Skipf("rootfs doesn't support shared mount, skip test %s", tID)
	}

	t.Parallel()
	base := testutil.NewBase(t)

	testCases := []struct {
		propagation string
		assertFunc  func(containerName, containerNameReplica string)
	}{
		{
			propagation: "rshared",
			assertFunc: func(containerName, containerNameReplica string) {
				// replica can get sub-mounts from original
				base.Cmd("exec", containerNameReplica, "cat", "/mnt1/replica/foo.txt").AssertOutExactly("toreplica")

				// and sub-mounts from replica will be propagated to the original too
				base.Cmd("exec", containerName, "cat", "/mnt1/bar/bar.txt").AssertOutExactly("fromreplica")
			},
		},
		{
			propagation: "rslave",
			assertFunc: func(containerName, containerNameReplica string) {
				// replica can get sub-mounts from original
				base.Cmd("exec", containerNameReplica, "cat", "/mnt1/replica/foo.txt").AssertOutExactly("toreplica")

				// but sub-mounts from replica will not be propagated to the original
				base.Cmd("exec", containerName, "cat", "/mnt1/bar/bar.txt").AssertFail()
			},
		},
		{
			propagation: "rprivate",
			assertFunc: func(containerName, containerNameReplica string) {
				// replica can't get sub-mounts from original
				base.Cmd("exec", containerNameReplica, "cat", "/mnt1/replica/foo.txt").AssertFail()
				// and sub-mounts from replica will not be propagated to the original too
				base.Cmd("exec", containerName, "cat", "/mnt1/bar/bar.txt").AssertFail()
			},
		},
		{
			propagation: "",
			assertFunc: func(containerName, containerNameReplica string) {
				// replica can't get sub-mounts from original
				base.Cmd("exec", containerNameReplica, "cat", "/mnt1/replica/foo.txt").AssertFail()
				// and sub-mounts from replica will not be propagated to the original too
				base.Cmd("exec", containerName, "cat", "/mnt1/bar/bar.txt").AssertFail()
			},
		},
	}

	for _, tc := range testCases {
		propagationName := tc.propagation
		if propagationName == "" {
			propagationName = "default"
		}

		t.Logf("Running test propagation case %s", propagationName)

		rwDir, err := os.MkdirTemp(t.TempDir(), "rw")
		if err != nil {
			t.Fatal(err)
		}

		containerName := tID + "-" + propagationName
		containerNameReplica := containerName + "-replica"

		mountOption := fmt.Sprintf("type=bind,src=%s,target=/mnt1,bind-propagation=%s", rwDir, tc.propagation)
		if tc.propagation == "" {
			mountOption = fmt.Sprintf("type=bind,src=%s,target=/mnt1", rwDir)
		}

		containers := []struct {
			name        string
			mountOption string
		}{
			{
				name:        containerName,
				mountOption: fmt.Sprintf("type=bind,src=%s,target=/mnt1,bind-propagation=rshared", rwDir),
			},
			{
				name:        containerNameReplica,
				mountOption: mountOption,
			},
		}
		for _, c := range containers {
			base.Cmd("run", "-d",
				"--privileged",
				"--name", c.name,
				"--mount", c.mountOption,
				testutil.AlpineImage,
				"top").AssertOK()
			defer base.Cmd("rm", "-f", c.name).Run()
		}

		// mount in the first container
		base.Cmd("exec", containerName, "sh", "-exc", "mkdir /app && mkdir /mnt1/replica && mount --bind /app /mnt1/replica && echo -n toreplica > /app/foo.txt").AssertOK()
		base.Cmd("exec", containerName, "cat", "/mnt1/replica/foo.txt").AssertOutExactly("toreplica")

		// mount in the second container
		base.Cmd("exec", containerNameReplica, "sh", "-exc", "mkdir /bar && mkdir /mnt1/bar").AssertOK()
		base.Cmd("exec", containerNameReplica, "sh", "-exc", "mount --bind /bar /mnt1/bar").AssertOK()

		base.Cmd("exec", containerNameReplica, "sh", "-exc", "echo -n fromreplica > /bar/bar.txt").AssertOK()
		base.Cmd("exec", containerNameReplica, "cat", "/mnt1/bar/bar.txt").AssertOutExactly("fromreplica")

		// call case specific assert function
		tc.assertFunc(containerName, containerNameReplica)

		// umount mount point in the first privileged container
		base.Cmd("exec", containerNameReplica, "sh", "-exc", "umount /mnt1/bar").AssertOK()
		base.Cmd("exec", containerName, "sh", "-exc", "umount /mnt1/replica").AssertOK()
	}
}

// isRootfsShareableMount will check if /tmp or / support shareable mount
func isRootfsShareableMount() bool {
	existFunc := func(mi mount.Info) bool {
		for _, opt := range strings.Split(mi.Optional, " ") {
			if strings.HasPrefix(opt, "shared:") {
				return true
			}
		}
		return false
	}

	mi, err := mount.Lookup("/tmp")
	if err == nil {
		return existFunc(mi)
	}

	mi, err = mount.Lookup("/")
	if err == nil {
		return existFunc(mi)
	}

	return false
}

func TestRunVolumesFrom(t *testing.T) {
	t.Parallel()
	base := testutil.NewBase(t)
	tID := testutil.Identifier(t)
	rwDir, err := os.MkdirTemp(t.TempDir(), "rw")
	if err != nil {
		t.Fatal(err)
	}
	roDir, err := os.MkdirTemp(t.TempDir(), "ro")
	if err != nil {
		t.Fatal(err)
	}
	rwVolName := tID + "-rw"
	roVolName := tID + "-ro"
	for _, v := range []string{rwVolName, roVolName} {
		defer base.Cmd("volume", "rm", "-f", v).Run()
		base.Cmd("volume", "create", v).AssertOK()
	}

	fromContainerName := tID + "-from"
	toContainerName := tID + "-to"
	defer base.Cmd("rm", "-f", fromContainerName).AssertOK()
	defer base.Cmd("rm", "-f", toContainerName).AssertOK()
	base.Cmd("run",
		"-d",
		"--name", fromContainerName,
		"-v", fmt.Sprintf("%s:/mnt1", rwDir),
		"-v", fmt.Sprintf("%s:/mnt2:ro", roDir),
		"-v", fmt.Sprintf("%s:/mnt3", rwVolName),
		"-v", fmt.Sprintf("%s:/mnt4:ro", roVolName),
		testutil.AlpineImage,
		"top",
	).AssertOK()
	base.Cmd("run",
		"-d",
		"--name", toContainerName,
		"--volumes-from", fromContainerName,
		testutil.AlpineImage,
		"top",
	).AssertOK()
	base.Cmd("exec", toContainerName, "sh", "-exc", "echo -n str1 > /mnt1/file1").AssertOK()
	base.Cmd("exec", toContainerName, "sh", "-exc", "echo -n str2 > /mnt2/file2").AssertFail()
	base.Cmd("exec", toContainerName, "sh", "-exc", "echo -n str3 > /mnt3/file3").AssertOK()
	base.Cmd("exec", toContainerName, "sh", "-exc", "echo -n str4 > /mnt4/file4").AssertFail()
	base.Cmd("rm", "-f", toContainerName).AssertOK()
	base.Cmd("run",
		"--rm",
		"--volumes-from", fromContainerName,
		testutil.AlpineImage,
		"cat", "/mnt1/file1", "/mnt3/file3",
	).AssertOutExactly("str1str3")
}

func TestBindMountWhenHostFolderDoesNotExist(t *testing.T) {
	t.Parallel()
	base := testutil.NewBase(t)
	containerName := testutil.Identifier(t) + "-host-dir-not-found"
	hostDir, err := os.MkdirTemp(t.TempDir(), "rw")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(hostDir)
	hp := filepath.Join(hostDir, "does-not-exist")
	base.Cmd("rm", "-f", containerName).AssertOK()
	base.Cmd("run", "--name", containerName, "-d", "-v", fmt.Sprintf("%s:/tmp",
		hp), testutil.AlpineImage).AssertOK()
	base.Cmd("rm", "-f", containerName).AssertOK()

	// Host directory should get created
	_, err = os.Stat(hp)
	assert.NilError(t, err)

	// Test for --mount
	os.RemoveAll(hp)
	base.Cmd("run", "--name", containerName, "-d", "--mount", fmt.Sprintf("type=bind, source=%s, target=/tmp",
		hp), testutil.AlpineImage).AssertFail()
	_, err = os.Stat(hp)
	assert.ErrorIs(t, err, os.ErrNotExist)
}
