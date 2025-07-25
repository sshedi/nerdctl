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
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/opencontainers/go-digest"
	"github.com/vishvananda/netlink"
	"gotest.tools/v3/assert"
	"gotest.tools/v3/icmd"

	"github.com/containerd/containerd/v2/defaults"
	"github.com/containerd/containerd/v2/pkg/netns"
	"github.com/containerd/nerdctl/mod/tigron/expect"
	"github.com/containerd/nerdctl/mod/tigron/require"
	"github.com/containerd/nerdctl/mod/tigron/test"
	"github.com/containerd/nerdctl/mod/tigron/tig"

	"github.com/containerd/nerdctl/v2/pkg/rootlessutil"
	"github.com/containerd/nerdctl/v2/pkg/testutil"
	"github.com/containerd/nerdctl/v2/pkg/testutil/nerdtest"
	"github.com/containerd/nerdctl/v2/pkg/testutil/nettestutil"
)

func extractHostPort(portMapping string, port string) (string, error) {
	// Regular expression to extract host port from port mapping information
	re := regexp.MustCompile(`(?P<containerPort>\d{1,5})/tcp ->.*?0.0.0.0:(?P<hostPort>\d{1,5}).*?`)
	portMappingLines := strings.Split(portMapping, "\n")
	for _, portMappingLine := range portMappingLines {
		// Find the matches
		matches := re.FindStringSubmatch(portMappingLine)
		// Check if there is a match
		if len(matches) >= 3 && matches[1] == port {
			// Extract the host port number
			hostPort := matches[2]
			return hostPort, nil
		}
	}
	return "", fmt.Errorf("could not extract host port from port mapping: %s", portMapping)
}

func valuesOfMapStringString(m map[string]string) map[string]struct{} {
	res := make(map[string]struct{})
	for _, v := range m {
		res[v] = struct{}{}
	}
	return res
}

// TestRunInternetConnectivity tests Internet connectivity with `apk update`
func TestRunInternetConnectivity(t *testing.T) {
	base := testutil.NewBase(t)
	customNet := testutil.Identifier(t)
	base.Cmd("network", "create", customNet).AssertOK()
	defer base.Cmd("network", "rm", customNet).Run()

	type testCase struct {
		args []string
	}
	customNetID := base.InspectNetwork(customNet).ID
	testCases := []testCase{
		{
			args: []string{"--net", "bridge"},
		},
		{
			args: []string{"--net", customNet},
		},
		{
			args: []string{"--net", customNetID},
		},
		{
			args: []string{"--net", customNetID[:12]},
		},
		{
			args: []string{"--net", "host"},
		},
	}
	for _, tc := range testCases {
		tc := tc // IMPORTANT
		name := "default"
		if len(tc.args) > 0 {
			name = strings.Join(tc.args, "_")
		}
		t.Run(name, func(t *testing.T) {
			args := []string{"run", "--rm"}
			args = append(args, tc.args...)
			args = append(args, testutil.AlpineImage, "apk", "update")
			cmd := base.Cmd(args...)
			cmd.AssertOutContains("OK")
		})
	}
}

// TestRunHostLookup tests hostname lookup
func TestRunHostLookup(t *testing.T) {
	base := testutil.NewBase(t)
	// key: container name, val: network name
	m := map[string]string{
		"c0-in-n0":     "n0",
		"c1-in-n0":     "n0",
		"c2-in-n1":     "n1",
		"c3-in-bridge": "bridge",
	}
	customNets := valuesOfMapStringString(m)
	defer func() {
		for name := range m {
			base.Cmd("rm", "-f", name).Run()
		}
		for netName := range customNets {
			if netName == "bridge" {
				continue
			}
			base.Cmd("network", "rm", netName).Run()
		}
	}()

	// Create networks
	for netName := range customNets {
		if netName == "bridge" {
			continue
		}
		base.Cmd("network", "create", netName).AssertOK()
	}

	// Create nginx containers
	for name, netName := range m {
		cmd := base.Cmd("run",
			"-d",
			"--name", name,
			"--hostname", name+"-foobar",
			"--net", netName,
			testutil.NginxAlpineImage,
		)
		t.Logf("creating host lookup testing container with command: %q", strings.Join(cmd.Command, " "))
		cmd.AssertOK()
	}

	testWget := func(srcContainer, targetHostname string, expected bool) {
		t.Logf("resolving %q in container %q (should success: %+v)", targetHostname, srcContainer, expected)
		cmd := base.Cmd("exec", srcContainer, "wget", "-qO-", "http://"+targetHostname)
		if expected {
			cmd.AssertOutContains(testutil.NginxAlpineIndexHTMLSnippet)
		} else {
			cmd.AssertFail()
		}
	}

	// Tests begin
	testWget("c0-in-n0", "c1-in-n0", true)
	testWget("c0-in-n0", "c1-in-n0.n0", true)
	testWget("c0-in-n0", "c1-in-n0-foobar", true)
	testWget("c0-in-n0", "c1-in-n0-foobar.n0", true)
	testWget("c0-in-n0", "c2-in-n1", false)
	testWget("c0-in-n0", "c2-in-n1.n1", false)
	testWget("c0-in-n0", "c3-in-bridge", false)
	testWget("c1-in-n0", "c0-in-n0", true)
	testWget("c1-in-n0", "c0-in-n0.n0", true)
	testWget("c1-in-n0", "c0-in-n0-foobar", true)
	testWget("c1-in-n0", "c0-in-n0-foobar.n0", true)
}

func TestRunPortWithNoHostPort(t *testing.T) {
	if rootlessutil.IsRootless() {
		t.Skip("Auto port assign is not supported rootless mode yet")
	}

	type testCase struct {
		containerPort    string
		runShouldSuccess bool
	}
	testCases := []testCase{
		{
			containerPort:    "80",
			runShouldSuccess: true,
		},
		{
			containerPort:    "80-81",
			runShouldSuccess: true,
		},
		{
			containerPort:    "80-81/tcp",
			runShouldSuccess: true,
		},
	}
	tID := testutil.Identifier(t)
	for i, tc := range testCases {
		i := i
		tc := tc
		tcName := fmt.Sprintf("%+v", tc)
		t.Run(tcName, func(t *testing.T) {
			testContainerName := fmt.Sprintf("%s-%d", tID, i)
			base := testutil.NewBase(t)
			defer base.Cmd("rm", "-f", testContainerName).Run()
			pFlag := tc.containerPort
			cmd := base.Cmd("run", "-d",
				"--name", testContainerName,
				"-p", pFlag,
				testutil.NginxAlpineImage)
			var result *icmd.Result
			stdoutContent := ""
			if tc.runShouldSuccess {
				cmd.AssertOK()
			} else {
				cmd.AssertFail()
				return
			}
			portCmd := base.Cmd("port", testContainerName)
			portCmd.Base.T.Helper()
			result = portCmd.Run()
			stdoutContent = result.Stdout() + result.Stderr()
			assert.Assert(cmd.Base.T, result.ExitCode == 0, stdoutContent)
			regexExpression := regexp.MustCompile(`80\/tcp.*?->.*?0.0.0.0:(?P<portNumber>\d{1,5}).*?`)
			match := regexExpression.FindStringSubmatch(stdoutContent)
			paramsMap := make(map[string]string)
			for i, name := range regexExpression.SubexpNames() {
				if i > 0 && i <= len(match) {
					paramsMap[name] = match[i]
				}
			}
			if _, ok := paramsMap["portNumber"]; !ok {
				t.Fail()
				return
			}
			connectURL := fmt.Sprintf("http://%s:%s", "127.0.0.1", paramsMap["portNumber"])
			resp, err := nettestutil.HTTPGet(connectURL, 5, false)
			assert.NilError(t, err)
			respBody, err := io.ReadAll(resp.Body)
			assert.NilError(t, err)
			assert.Assert(t, strings.Contains(string(respBody), testutil.NginxAlpineIndexHTMLSnippet))
		})
	}

}

func TestUniqueHostPortAssignement(t *testing.T) {
	if rootlessutil.IsRootless() {
		t.Skip("Auto port assign is not supported rootless mode yet")
	}

	type testCase struct {
		containerPort    string
		runShouldSuccess bool
	}

	testCases := []testCase{
		{
			containerPort:    "80",
			runShouldSuccess: true,
		},
		{
			containerPort:    "80-81",
			runShouldSuccess: true,
		},
		{
			containerPort:    "80-81/tcp",
			runShouldSuccess: true,
		},
	}

	tID := testutil.Identifier(t)

	for i, tc := range testCases {
		i := i
		tc := tc
		tcName := fmt.Sprintf("%+v", tc)
		t.Run(tcName, func(t *testing.T) {
			testContainerName1 := fmt.Sprintf("%s-%d-1", tID, i)
			testContainerName2 := fmt.Sprintf("%s-%d-2", tID, i)
			base := testutil.NewBase(t)
			defer base.Cmd("rm", "-f", testContainerName1, testContainerName2).Run()

			pFlag := tc.containerPort
			cmd1 := base.Cmd("run", "-d",
				"--name", testContainerName1, "-p",
				pFlag,
				testutil.NginxAlpineImage)

			cmd2 := base.Cmd("run", "-d",
				"--name", testContainerName2, "-p",
				pFlag,
				testutil.NginxAlpineImage)
			var result *icmd.Result
			stdoutContent := ""
			if tc.runShouldSuccess {
				cmd1.AssertOK()
				cmd2.AssertOK()
			} else {
				cmd1.AssertFail()
				cmd2.AssertFail()
				return
			}
			portCmd1 := base.Cmd("port", testContainerName1)
			portCmd2 := base.Cmd("port", testContainerName2)
			portCmd1.Base.T.Helper()
			portCmd2.Base.T.Helper()
			result = portCmd1.Run()
			stdoutContent = result.Stdout() + result.Stderr()
			assert.Assert(t, result.ExitCode == 0, stdoutContent)
			port1, err := extractHostPort(stdoutContent, "80")
			assert.NilError(t, err)
			result = portCmd2.Run()
			stdoutContent = result.Stdout() + result.Stderr()
			assert.Assert(t, result.ExitCode == 0, stdoutContent)
			port2, err := extractHostPort(stdoutContent, "80")
			assert.NilError(t, err)
			assert.Assert(t, port1 != port2, "Host ports are not unique")

			// Make HTTP GET request to container 1
			connectURL1 := fmt.Sprintf("http://%s:%s", "127.0.0.1", port1)
			resp1, err := nettestutil.HTTPGet(connectURL1, 5, false)
			assert.NilError(t, err)
			respBody1, err := io.ReadAll(resp1.Body)
			assert.NilError(t, err)
			assert.Assert(t, strings.Contains(string(respBody1), testutil.NginxAlpineIndexHTMLSnippet))

			// Make HTTP GET request to container 2
			connectURL2 := fmt.Sprintf("http://%s:%s", "127.0.0.1", port2)
			resp2, err := nettestutil.HTTPGet(connectURL2, 5, false)
			assert.NilError(t, err)
			respBody2, err := io.ReadAll(resp2.Body)
			assert.NilError(t, err)
			assert.Assert(t, strings.Contains(string(respBody2), testutil.NginxAlpineIndexHTMLSnippet))
		})
	}
}

func TestHostPortAlreadyInUse(t *testing.T) {
	testCases := []struct {
		hostPort      string
		containerPort string
	}{
		{
			hostPort:      "5000",
			containerPort: "80/tcp",
		},
		{
			hostPort:      "5000",
			containerPort: "80/tcp",
		},
		{
			hostPort:      "5000",
			containerPort: "80/udp",
		},
		{
			hostPort:      "5000",
			containerPort: "80/sctp",
		},
	}

	tID := testutil.Identifier(t)

	for i, tc := range testCases {
		tc := tc
		tcName := fmt.Sprintf("%+v", tc)
		t.Run(tcName, func(t *testing.T) {
			if strings.Contains(tc.containerPort, "sctp") && rootlessutil.IsRootless() {
				t.Skip("sctp is not supported in rootless mode")
			}
			testContainerName1 := fmt.Sprintf("%s-%d-1", tID, i)
			testContainerName2 := fmt.Sprintf("%s-%d-2", tID, i)
			base := testutil.NewBase(t)
			t.Cleanup(func() {
				base.Cmd("rm", "-f", testContainerName1, testContainerName2).AssertOK()
			})
			pFlag := fmt.Sprintf("%s:%s", tc.hostPort, tc.containerPort)
			cmd1 := base.Cmd("run", "-d",
				"--name", testContainerName1, "-p",
				pFlag,
				testutil.NginxAlpineImage)

			cmd2 := base.Cmd("run", "-d",
				"--name", testContainerName2, "-p",
				pFlag,
				testutil.NginxAlpineImage)

			cmd1.AssertOK()
			cmd2.AssertFail()
		})
	}
}

func TestRunPort(t *testing.T) {
	baseTestRunPort(t, testutil.NginxAlpineImage, testutil.NginxAlpineIndexHTMLSnippet, true)
}

func TestRunWithManyPortsThenCleanUp(t *testing.T) {
	testCase := nerdtest.Setup()
	// docker does not set label restriction to 4096 bytes
	testCase.Require = require.Not(nerdtest.Docker)

	testCase.SubTests = []*test.Case{
		{
			Description: "Run a container with many ports, and then clean up.",
			Command: func(data test.Data, helpers test.Helpers) test.TestableCommand {
				return helpers.Command("run", "--data-root", data.Temp().Path(), "--rm", "-p", "22200-22299:22200-22299", testutil.CommonImage)
			},
			Expected: func(data test.Data, helpers test.Helpers) *test.Expected {
				return &test.Expected{
					ExitCode: 0,
					Errors:   []error{},
					Output: func(stdout string, t tig.T) {
						getAddrHash := func(addr string) string {
							const addrHashLen = 8

							d := digest.SHA256.FromString(addr)
							h := d.Encoded()[0:addrHashLen]

							return h
						}

						dataRoot := data.Temp().Path()
						h := getAddrHash(defaults.DefaultAddress)
						dataStore := filepath.Join(dataRoot, h)
						namespace := string(helpers.Read(nerdtest.Namespace))
						etchostsPath := filepath.Join(dataStore, "etchosts", namespace)

						etchostsDirs, err := os.ReadDir(etchostsPath)

						assert.NilError(t, err)
						assert.Equal(t, len(etchostsDirs), 0)
					},
				}
			},
		},
	}

	testCase.Run(t)
}

func TestRunContainerWithStaticIP(t *testing.T) {
	if rootlessutil.IsRootless() {
		t.Skip("Static IP assignment is not supported rootless mode yet.")
	}
	networkName := "test-network"
	networkSubnet := "172.0.0.0/16"
	base := testutil.NewBase(t)
	cmd := base.Cmd("network", "create", networkName, "--subnet", networkSubnet)
	cmd.AssertOK()
	defer base.Cmd("network", "rm", networkName).Run()
	testCases := []struct {
		ip                string
		shouldSuccess     bool
		useNetwork        bool
		checkTheIPAddress bool
	}{
		{
			ip:                "172.0.0.2",
			shouldSuccess:     true,
			useNetwork:        true,
			checkTheIPAddress: true,
		},
		{
			ip:                "192.0.0.2",
			shouldSuccess:     false,
			useNetwork:        true,
			checkTheIPAddress: false,
		},
		// XXX see https://github.com/containerd/nerdctl/issues/3101
		// docker 24 silently ignored the ip - now, docker 26 is erroring out - furthermore, this ip only makes sense
		// in the context of nerdctl bridge network, so, this test needs rewritting either way
		/*
			{
				ip:                "10.4.0.2",
				shouldSuccess:     true,
				useNetwork:        false,
				checkTheIPAddress: false,
			},
		*/
	}
	tID := testutil.Identifier(t)
	for i, tc := range testCases {
		i := i
		tc := tc
		tcName := fmt.Sprintf("%+v", tc)
		t.Run(tcName, func(t *testing.T) {
			testContainerName := fmt.Sprintf("%s-%d", tID, i)
			base := testutil.NewBase(t)
			defer base.Cmd("rm", "-f", testContainerName).Run()
			args := []string{
				"run", "-d", "--name", testContainerName,
			}
			if tc.useNetwork {
				args = append(args, []string{"--network", networkName}...)
			}
			args = append(args, []string{"--ip", tc.ip, testutil.NginxAlpineImage}...)
			cmd := base.Cmd(args...)
			if !tc.shouldSuccess {
				cmd.AssertFail()
				return
			}
			cmd.AssertOK()

			if tc.checkTheIPAddress {
				inspectCmd := base.Cmd("inspect", testContainerName, "--format", "\"{{range .NetworkSettings.Networks}} {{.IPAddress}}{{end}}\"")
				result := inspectCmd.Run()
				stdoutContent := result.Stdout() + result.Stderr()
				assert.Assert(inspectCmd.Base.T, result.ExitCode == 0, stdoutContent)
				if !strings.Contains(stdoutContent, tc.ip) {
					t.Fail()
					return
				}
			}
		})
	}
}

func TestRunDNS(t *testing.T) {
	base := testutil.NewBase(t)

	base.Cmd("run", "--rm", "--dns", "8.8.8.8", testutil.CommonImage,
		"cat", "/etc/resolv.conf").AssertOutContains("nameserver 8.8.8.8\n")
	base.Cmd("run", "--rm", "--dns-search", "test", testutil.CommonImage,
		"cat", "/etc/resolv.conf").AssertOutContains("search test\n")
	base.Cmd("run", "--rm", "--dns-search", "test", "--dns-search", "test1", testutil.CommonImage,
		"cat", "/etc/resolv.conf").AssertOutContains("search test test1\n")
	base.Cmd("run", "--rm", "--dns-opt", "no-tld-query", "--dns-option", "attempts:10", testutil.CommonImage,
		"cat", "/etc/resolv.conf").AssertOutContains("options no-tld-query attempts:10\n")
	cmd := base.Cmd("run", "--rm", "--dns", "8.8.8.8", "--dns-search", "test", "--dns-option", "attempts:10", testutil.CommonImage,
		"cat", "/etc/resolv.conf")
	cmd.AssertOutContains("nameserver 8.8.8.8\n")
	cmd.AssertOutContains("search test\n")
	cmd.AssertOutContains("options attempts:10\n")
}

func TestRunNetworkHostHostname(t *testing.T) {
	base := testutil.NewBase(t)

	hostname, err := os.Hostname()
	assert.NilError(t, err)
	hostname = hostname + "\n"
	base.Cmd("run", "--rm", "--network", "host", testutil.CommonImage, "hostname").AssertOutExactly(hostname)
	base.Cmd("run", "--rm", "--network", "host", testutil.CommonImage, "sh", "-euxc", "echo $HOSTNAME").AssertOutExactly(hostname)
	base.Cmd("run", "--rm", "--network", "host", "--hostname", "override", testutil.CommonImage, "hostname").AssertOutExactly("override\n")
	base.Cmd("run", "--rm", "--network", "host", "--hostname", "override", testutil.CommonImage, "sh", "-euxc", "echo $HOSTNAME").AssertOutExactly("override\n")
}

func TestRunNetworkHost2613(t *testing.T) {
	base := testutil.NewBase(t)

	base.Cmd("run", "--rm", "--add-host", "foo:1.2.3.4", testutil.CommonImage, "getent", "hosts", "foo").AssertOutExactly("1.2.3.4           foo  foo\n")
}

func TestSharedNetworkSetup(t *testing.T) {
	nerdtest.Setup()
	testCase := &test.Case{
		Require: require.Not(require.Windows),
		Setup: func(data test.Data, helpers test.Helpers) {
			data.Labels().Set("container1", data.Identifier("container1"))
			helpers.Ensure("run", "-d", "--name", data.Identifier("container1"),
				testutil.CommonImage, "sleep", "inf")
			nerdtest.EnsureContainerStarted(helpers, data.Identifier("container1"))
		},
		Cleanup: func(data test.Data, helpers test.Helpers) {
			helpers.Anyhow("rm", "-f", data.Identifier("container1"))
		},
		SubTests: []*test.Case{
			{
				Description: "Test network is shared",
				NoParallel:  true, // The validation involves starting of the main container: container1
				Cleanup: func(data test.Data, helpers test.Helpers) {
					helpers.Anyhow("rm", "-f", data.Identifier("container2"))
				},
				Setup: func(data test.Data, helpers test.Helpers) {
					helpers.Ensure(
						"run", "-d", "--name", data.Identifier("container2"),
						"--network=container:"+data.Labels().Get("container1"),
						testutil.NginxAlpineImage)
					data.Labels().Set("container2", data.Identifier("container2"))
					nerdtest.EnsureContainerStarted(helpers, data.Identifier("container2"))
				},
				SubTests: []*test.Case{
					{
						NoParallel:  true,
						Description: "Test network is shared",
						Command: func(data test.Data, helpers test.Helpers) test.TestableCommand {
							return helpers.Command("exec", data.Labels().Get("container2"), "wget", "-qO-", "http://127.0.0.1:80")
						},
						Expected: test.Expects(0, nil, expect.Contains(testutil.NginxAlpineIndexHTMLSnippet)),
					},
					{
						NoParallel:  true,
						Description: "Test network is shared after restart",
						Setup: func(data test.Data, helpers test.Helpers) {
							helpers.Ensure("restart", data.Labels().Get("container1"))
							helpers.Ensure("stop", "--time=1", data.Labels().Get("container2"))
							helpers.Ensure("start", data.Labels().Get("container2"))
							nerdtest.EnsureContainerStarted(helpers, data.Labels().Get("container2"))
						},
						Command: func(data test.Data, helpers test.Helpers) test.TestableCommand {
							return helpers.Command("exec", data.Labels().Get("container2"), "wget", "-qO-", "http://127.0.0.1:80")

						},
						Expected: test.Expects(0, nil, expect.Contains(testutil.NginxAlpineIndexHTMLSnippet)),
					},
				},
			},
			{
				Description: "Test uts is supported in shared network",
				Command: func(data test.Data, helpers test.Helpers) test.TestableCommand {
					return helpers.Command("run", "--rm", "--uts", "host",
						"--network=container:"+data.Labels().Get("container1"),
						testutil.CommonImage)
				},
				Expected: test.Expects(0, nil, nil),
			},
			{
				Description: "Test dns is not supported",
				Command: func(data test.Data, helpers test.Helpers) test.TestableCommand {
					return helpers.Command("run", "--rm", "--dns", "0.1.2.3",
						"--network=container:"+data.Labels().Get("container1"),
						testutil.CommonImage)
				},
				// 1 for nerdctl, 125 for docker
				Expected: test.Expects(expect.ExitCodeGenericFail, nil, nil),
			},
			{
				Description: "Test dns options is not  supported",
				Command: func(data test.Data, helpers test.Helpers) test.TestableCommand {
					return helpers.Command("run", "--rm", "--dns-option", "attempts:5",
						"--network=container:"+data.Labels().Get("container1"),
						testutil.CommonImage, "cat", "/etc/resolv.conf")
				},
				// The Option doesn't throw an error but is never inserted to the resolv.conf
				Expected: test.Expects(0, nil, expect.DoesNotContain("attempts:5")),
			},
			{
				Description: "Test publish is not supported",
				Command: func(data test.Data, helpers test.Helpers) test.TestableCommand {
					return helpers.Command("run", "--rm", "--publish", "80:8080",
						"--network=container:"+data.Labels().Get("container1"),
						testutil.AlpineImage)
				},
				// 1 for nerdctl, 125 for docker
				Expected: test.Expects(expect.ExitCodeGenericFail, nil, nil),
			},
			{
				Description: "Test hostname is not supported",
				Command: func(data test.Data, helpers test.Helpers) test.TestableCommand {
					return helpers.Command("run", "--rm", "--hostname", "test",
						"--network=container:"+data.Labels().Get("container1"),
						testutil.AlpineImage)
				},
				// 1 for nerdctl, 125 for docker
				Expected: test.Expects(expect.ExitCodeGenericFail, nil, nil),
			},
		},
	}
	testCase.Run(t)
}

func TestSharedNetworkWithNone(t *testing.T) {
	nerdtest.Setup()
	testCase := &test.Case{
		Require: require.Not(require.Windows),
		Setup: func(data test.Data, helpers test.Helpers) {
			helpers.Ensure("run", "-d", "--name", data.Identifier("container1"), "--network", "none",
				testutil.CommonImage, "sleep", "inf")
			nerdtest.EnsureContainerStarted(helpers, data.Identifier("container1"))
		},
		Cleanup: func(data test.Data, helpers test.Helpers) {
			helpers.Anyhow("rm", "-f", data.Identifier("container1"))
		},
		Command: func(data test.Data, helpers test.Helpers) test.TestableCommand {
			return helpers.Command("run", "--rm",
				"--network=container:"+data.Identifier("container1"), testutil.CommonImage)
		},
		Expected: test.Expects(expect.ExitCodeSuccess, nil, nil),
	}
	testCase.Run(t)
}

func TestRunContainerInExistingNetNS(t *testing.T) {
	if rootlessutil.IsRootless() {
		t.Skip("Can't create new netns in rootless mode")
	}
	testutil.DockerIncompatible(t)
	base := testutil.NewBase(t)

	netNS, err := netns.NewNetNS(t.TempDir() + "/netns")
	assert.NilError(t, err)
	err = netNS.Do(func(netns ns.NetNS) error {
		loopback, err := netlink.LinkByName("lo")
		assert.NilError(t, err)
		err = netlink.LinkSetUp(loopback)
		assert.NilError(t, err)
		return nil
	})
	assert.NilError(t, err)
	defer netNS.Remove()

	containerName := testutil.Identifier(t)
	defer base.Cmd("rm", "-f", containerName).AssertOK()
	base.Cmd("run", "-d", "--name", containerName,
		"--network=ns:"+netNS.GetPath(), testutil.NginxAlpineImage).AssertOK()
	base.EnsureContainerStarted(containerName)
	time.Sleep(3 * time.Second)

	err = netNS.Do(func(netns ns.NetNS) error {
		stdout, err := exec.Command("curl", "-s", "http://127.0.0.1:80").Output()
		assert.NilError(t, err)
		assert.Assert(t, strings.Contains(string(stdout), testutil.NginxAlpineIndexHTMLSnippet))
		return nil
	})
	assert.NilError(t, err)
}

func TestRunContainerWithMACAddress(t *testing.T) {
	base := testutil.NewBase(t)
	tID := testutil.Identifier(t)
	networkBridge := "testNetworkBridge" + tID
	networkMACvlan := "testNetworkMACvlan" + tID
	networkIPvlan := "testNetworkIPvlan" + tID
	tearDown := func() {
		base.Cmd("network", "rm", networkBridge).Run()
		base.Cmd("network", "rm", networkMACvlan).Run()
		base.Cmd("network", "rm", networkIPvlan).Run()
	}

	tearDown()
	t.Cleanup(tearDown)

	base.Cmd("network", "create", networkBridge, "--driver", "bridge").AssertOK()
	base.Cmd("network", "create", networkMACvlan, "--driver", "macvlan").AssertOK()
	base.Cmd("network", "create", networkIPvlan, "--driver", "ipvlan").AssertOK()

	defaultMac := base.Cmd("run", "--rm", "-i", "--network", "host", testutil.CommonImage).
		CmdOption(testutil.WithStdin(strings.NewReader("ip addr show eth0 | grep ether | awk '{printf $2}'"))).
		Run().Stdout()

	passedMac := "we expect the generated mac on the output"

	tests := []struct {
		Network string
		WantErr bool
		Expect  string
	}{
		{"host", false, defaultMac},                     // anything but the actual address being passed
		{"none", false, ""},                             // nothing
		{"container:whatever" + tID, true, "container"}, // "No such container" vs. "could not find container"
		{"bridge", false, passedMac},
		{networkBridge, false, passedMac},
		{networkMACvlan, false, passedMac},
		{networkIPvlan, true, "not support"},
	}

	for i, test := range tests {
		containerName := fmt.Sprintf("%s_%d", tID, i)
		testName := fmt.Sprintf("%s_container:%s_network:%s_expect:%s", tID, containerName, test.Network, test.Expect)
		expect := test.Expect
		network := test.Network
		wantErr := test.WantErr
		t.Run(testName, func(tt *testing.T) {
			tt.Parallel()

			macAddress, err := nettestutil.GenerateMACAddress()
			if err != nil {
				t.Errorf("failed to generate MAC address: %s", err)
			}
			if expect == passedMac {
				expect = macAddress
			}

			res := base.Cmd("run", "--rm", "-i", "--network", network, "--mac-address", macAddress, testutil.CommonImage).
				CmdOption(testutil.WithStdin(strings.NewReader("ip addr show eth0 | grep ether | awk '{printf $2}'"))).Run()

			if wantErr {
				assert.Assert(t, res.ExitCode != 0, "Command should have failed", res)
				assert.Assert(t, strings.Contains(res.Combined(), expect), fmt.Sprintf("expected output to contain %q: %q", expect, res.Combined()))
			} else {
				assert.Assert(t, res.ExitCode == 0, "Command should have succeeded", res)
				assert.Assert(t, strings.Contains(res.Stdout(), expect), fmt.Sprintf("expected output to contain %q: %q", expect, res.Stdout()))
			}
		})

	}
}

func TestHostsFileMounts(t *testing.T) {
	if rootlessutil.IsRootless() {
		if detachedNetNS, _ := rootlessutil.DetachedNetNS(); detachedNetNS != "" {
			t.Skip("/etc/hosts is not writable")
		}
	}
	base := testutil.NewBase(t)

	base.Cmd("run", "--rm", testutil.CommonImage,
		"sh", "-euxc", "echo >> /etc/hosts").AssertOK()
	base.Cmd("run", "--rm", "--network", "host", testutil.CommonImage,
		"sh", "-euxc", "echo >> /etc/hosts").AssertOK()
	base.Cmd("run", "--rm", "-v", "/etc/hosts:/etc/hosts:ro", "--network", "host", testutil.CommonImage,
		"sh", "-euxc", "echo >> /etc/hosts").AssertFail()
	// add a line into /etc/hosts and remove it.
	base.Cmd("run", "--rm", "-v", "/etc/hosts:/etc/hosts", "--network", "host", testutil.CommonImage,
		"sh", "-euxc", "echo >> /etc/hosts").AssertOK()
	base.Cmd("run", "--rm", "-v", "/etc/hosts:/etc/hosts", "--network", "host", testutil.CommonImage,
		"sh", "-euxc", "head -n -1 /etc/hosts > temp && cat temp > /etc/hosts").AssertOK()
	base.Cmd("run", "--rm", "--network", "none", testutil.CommonImage,
		"sh", "-euxc", "echo >> /etc/hosts").AssertOK()

	base.Cmd("run", "--rm", testutil.CommonImage,
		"sh", "-euxc", "echo >> /etc/resolv.conf").AssertOK()
	base.Cmd("run", "--rm", "--network", "host", testutil.CommonImage,
		"sh", "-euxc", "echo >> /etc/resolv.conf").AssertOK()
	base.Cmd("run", "--rm", "-v", "/etc/resolv.conf:/etc/resolv.conf:ro", "--network", "host", testutil.CommonImage,
		"sh", "-euxc", "echo >> /etc/resolv.conf").AssertFail()
	// add a line into /etc/resolv.conf and remove it.
	base.Cmd("run", "--rm", "-v", "/etc/resolv.conf:/etc/resolv.conf", "--network", "host", testutil.CommonImage,
		"sh", "-euxc", "echo >> /etc/resolv.conf").AssertOK()
	base.Cmd("run", "--rm", "-v", "/etc/resolv.conf:/etc/resolv.conf", "--network", "host", testutil.CommonImage,
		"sh", "-euxc", "head -n -1 /etc/resolv.conf > temp && cat temp > /etc/resolv.conf").AssertOK()
	base.Cmd("run", "--rm", "--network", "host", testutil.CommonImage,
		"sh", "-euxc", "echo >> /etc/resolv.conf").AssertOK()
}

func TestRunContainerWithStaticIP6(t *testing.T) {
	if rootlessutil.IsRootless() {
		t.Skip("Static IP6 assignment is not supported rootless mode yet.")
	}
	networkName := "test-network"
	networkSubnet := "2001:db8:5::/64"
	_, subnet, err := net.ParseCIDR(networkSubnet)
	assert.Assert(t, err == nil)
	base := testutil.NewBaseWithIPv6Compatible(t)
	base.Cmd("network", "create", networkName, "--subnet", networkSubnet, "--ipv6").AssertOK()
	t.Cleanup(func() {
		base.Cmd("network", "rm", networkName).Run()
	})
	testCases := []struct {
		ip                string
		shouldSuccess     bool
		checkTheIPAddress bool
	}{
		{
			ip:                "",
			shouldSuccess:     true,
			checkTheIPAddress: false,
		},
		{
			ip:                "2001:db8:5::6",
			shouldSuccess:     true,
			checkTheIPAddress: true,
		},
		{
			ip:                "2001:db8:4::6",
			shouldSuccess:     false,
			checkTheIPAddress: false,
		},
	}
	tID := testutil.Identifier(t)
	for i, tc := range testCases {
		i := i
		tc := tc
		tcName := fmt.Sprintf("%+v", tc)
		t.Run(tcName, func(t *testing.T) {
			testContainerName := fmt.Sprintf("%s-%d", tID, i)
			base := testutil.NewBaseWithIPv6Compatible(t)
			args := []string{
				"run", "--rm", "--name", testContainerName, "--network", networkName,
			}
			if tc.ip != "" {
				args = append(args, "--ip6", tc.ip)
			}
			args = append(args, []string{testutil.NginxAlpineImage, "ip", "addr", "show", "dev", "eth0"}...)
			cmd := base.Cmd(args...)
			if !tc.shouldSuccess {
				cmd.AssertFail()
				return
			}
			cmd.AssertOutWithFunc(func(stdout string) error {
				ip := nerdtest.FindIPv6(stdout)
				if !subnet.Contains(ip) {
					return fmt.Errorf("expected subnet %s include ip %s", subnet, ip)
				}
				if tc.checkTheIPAddress {
					if ip.String() != tc.ip {
						return fmt.Errorf("expected ip %s, got %s", tc.ip, ip)
					}
				}
				return nil
			})
		})
	}
}

func TestNoneNetworkHostName(t *testing.T) {
	nerdtest.Setup()
	testCase := &test.Case{
		Require: require.Not(require.Windows),
		Cleanup: func(data test.Data, helpers test.Helpers) {
			helpers.Anyhow("rm", "-f", data.Identifier())
		},
		Setup: func(data test.Data, helpers test.Helpers) {
			output := helpers.Capture("run", "-d", "--name", data.Identifier(), "--network", "none", testutil.CommonImage, "sleep", "inf")
			assert.Assert(helpers.T(), len(output) > 12, output)
			data.Labels().Set("hostname", output[:12])
			nerdtest.EnsureContainerStarted(helpers, data.Identifier())
		},
		Command: func(data test.Data, helpers test.Helpers) test.TestableCommand {
			return helpers.Command("exec", data.Identifier(), "cat", "/etc/hostname")
		},
		Expected: func(data test.Data, helpers test.Helpers) *test.Expected {
			return &test.Expected{
				Output: expect.Equals(data.Labels().Get("hostname") + "\n"),
			}
		},
	}
	testCase.Run(t)
}

func TestHostNetworkHostName(t *testing.T) {
	nerdtest.Setup()
	testCase := &test.Case{
		Require: require.Not(require.Windows),
		Setup: func(data test.Data, helpers test.Helpers) {
			helpers.Custom("cat", "/etc/hostname").Run(&test.Expected{
				Output: func(stdout string, t tig.T) {
					data.Labels().Set("hostHostname", stdout)
				},
			})
		},
		Command: func(data test.Data, helpers test.Helpers) test.TestableCommand {
			return helpers.Command("run", "--rm",
				"--network", "host",
				testutil.AlpineImage, "cat", "/etc/hostname")
		},
		Expected: func(data test.Data, helpers test.Helpers) *test.Expected {
			return &test.Expected{
				Output: expect.Equals(data.Labels().Get("hostHostname")),
			}
		},
	}
	testCase.Run(t)
}

func TestNoneNetworkDnsConfigs(t *testing.T) {
	nerdtest.Setup()
	testCase := &test.Case{
		Require: require.Not(require.Windows),
		Command: func(data test.Data, helpers test.Helpers) test.TestableCommand {
			return helpers.Command("run", "--rm",
				"--network", "none",
				"--dns", "0.1.2.3", "--dns-search", "example.com", "--dns-option", "timeout:3", "--dns-option", "attempts:5",
				testutil.CommonImage, "cat", "/etc/resolv.conf")
		},
		Expected: test.Expects(0, nil, expect.Contains(
			"0.1.2.3",
			"example.com",
			"attempts:5",
			"timeout:3",
		)),
	}
	testCase.Run(t)
}

func TestHostNetworkDnsConfigs(t *testing.T) {
	nerdtest.Setup()
	testCase := &test.Case{
		Require: require.Not(require.Windows),
		Command: func(data test.Data, helpers test.Helpers) test.TestableCommand {
			return helpers.Command("run", "--rm",
				"--network", "host",
				"--dns", "0.1.2.3", "--dns-search", "example.com", "--dns-option", "timeout:3", "--dns-option", "attempts:5",
				testutil.CommonImage, "cat", "/etc/resolv.conf")
		},
		Expected: test.Expects(0, nil, expect.Contains(
			"0.1.2.3",
			"example.com",
			"attempts:5",
			"timeout:3",
		)),
	}
	testCase.Run(t)
}

func TestDNSWithGlobalConfig(t *testing.T) {
	var configContent test.ConfigValue = `debug = false
debug_full = false
dns = ["10.10.10.10", "20.20.20.20"]
dns_opts = ["ndots:2", "timeout:5"]
dns_search = ["example.com", "test.local"]`

	nerdtest.Setup()

	testCase := &test.Case{
		Config: test.WithConfig(nerdtest.NerdctlToml, configContent),
		// NERDCTL_TOML not supported in Docker
		Require: require.Not(nerdtest.Docker),
		SubTests: []*test.Case{
			{
				Description: "Global DNS settings are used when command line options are not provided",
				Command: func(data test.Data, helpers test.Helpers) test.TestableCommand {
					nerdctlTomlContent := string(helpers.Read(nerdtest.NerdctlToml))
					helpers.T().Log("NERDCTL_TOML file content:\n%s", nerdctlTomlContent)
					cmd := helpers.Command("run", "--rm", testutil.CommonImage, "cat", "/etc/resolv.conf")
					return cmd
				},
				Expected: test.Expects(expect.ExitCodeSuccess, nil, expect.All(
					expect.Contains("nameserver 10.10.10.10"),
					expect.Contains("nameserver 20.20.20.20"),
					expect.Contains("search example.com test.local"),
					expect.Contains("options ndots:2 timeout:5"),
				)),
			},
			{
				Description: "Command line DNS options override global config",
				Command: func(data test.Data, helpers test.Helpers) test.TestableCommand {
					nerdctlTomlContent := string(helpers.Read(nerdtest.NerdctlToml))
					helpers.T().Log("NERDCTL_TOML file content:\n%s", nerdctlTomlContent)
					cmd := helpers.Command("run", "--rm",
						"--dns", "9.9.9.9",
						"--dns-search", "override.com",
						"--dns-opt", "ndots:3",
						testutil.CommonImage, "cat", "/etc/resolv.conf")
					return cmd
				},
				Expected: test.Expects(expect.ExitCodeSuccess, nil, expect.All(
					expect.Contains("nameserver 9.9.9.9"),
					expect.Contains("search override.com"),
					expect.Contains("options ndots:3"),
				)),
			},
			{
				Description: "Global DNS settings should also apply when using host network",
				Command: func(data test.Data, helpers test.Helpers) test.TestableCommand {
					nerdctlTomlContent := string(helpers.Read(nerdtest.NerdctlToml))
					helpers.T().Log("NERDCTL_TOML file content:\n%s", nerdctlTomlContent)
					cmd := helpers.Command("run", "--rm", "--network", "host",
						testutil.CommonImage, "cat", "/etc/resolv.conf")
					return cmd
				},
				Expected: test.Expects(expect.ExitCodeSuccess, nil, expect.All(
					expect.Contains("nameserver 10.10.10.10"),
					expect.Contains("nameserver 20.20.20.20"),
					expect.Contains("search example.com test.local"),
					expect.Contains("options ndots:2 timeout:5"),
				)),
			},
			{
				Description: "Global DNS settings should also apply when using none network",
				Command: func(data test.Data, helpers test.Helpers) test.TestableCommand {
					nerdctlTomlContent := string(helpers.Read(nerdtest.NerdctlToml))
					helpers.T().Log("NERDCTL_TOML file content:\n%s", nerdctlTomlContent)
					cmd := helpers.Command("run", "--rm", "--network", "none",
						testutil.CommonImage, "cat", "/etc/resolv.conf")
					return cmd
				},
				Expected: test.Expects(expect.ExitCodeSuccess, nil, expect.All(
					expect.Contains("nameserver 10.10.10.10"),
					expect.Contains("nameserver 20.20.20.20"),
					expect.Contains("search example.com test.local"),
					expect.Contains("options ndots:2 timeout:5"),
				)),
			},
		},
	}
	testCase.Run(t)
}
