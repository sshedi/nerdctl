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

package portutil

import (
	"reflect"
	"runtime"
	"sort"
	"testing"

	"gotest.tools/v3/assert"

	"github.com/containerd/go-cni"

	"github.com/containerd/nerdctl/v2/pkg/labels"
	"github.com/containerd/nerdctl/v2/pkg/rootlessutil"
)

func TestTestParseFlagPWithPlatformSpec(t *testing.T) {
	if runtime.GOOS != "linux" || rootlessutil.IsRootless() {
		t.Skip("no non-Linux platform or rootless mode in Linux are not supported yet")
	}
	type args struct {
		s string
	}
	tests := []struct {
		name    string
		args    args
		want    []cni.PortMapping
		wantErr bool
	}{
		{
			name: "without colon",
			args: args{
				s: "3000",
			},
			want: []cni.PortMapping{
				{
					ContainerPort: 3000,
					Protocol:      "tcp",
					HostIP:        "0.0.0.0",
				},
			},
			wantErr: false,
		},
		{
			name: "Enable auto host port",
			args: args{
				s: "3000-3001",
			},
			want: []cni.PortMapping{
				{
					ContainerPort: 3000,
					Protocol:      "tcp",
					HostIP:        "0.0.0.0",
				},
				{
					ContainerPort: 3001,
					Protocol:      "tcp",
					HostIP:        "0.0.0.0",
				},
			},
			wantErr: false,
		},
		{
			name: "Enable auto host port error",
			args: args{
				s: "49153-61000",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Enable auto host port with tcp protocol",
			args: args{
				s: "3000-3001/tcp",
			},
			want: []cni.PortMapping{
				{
					ContainerPort: 3000,
					Protocol:      "tcp",
					HostIP:        "0.0.0.0",
				},
				{
					ContainerPort: 3001,
					Protocol:      "tcp",
					HostIP:        "0.0.0.0",
				},
			},
			wantErr: false,
		},
		{
			name: "Enable auto host port with udp protocol",
			args: args{
				s: "3000-3001/udp",
			},
			want: []cni.PortMapping{
				{
					ContainerPort: 3000,
					Protocol:      "udp",
					HostIP:        "0.0.0.0",
				},
				{
					ContainerPort: 3001,
					Protocol:      "udp",
					HostIP:        "0.0.0.0",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseFlagP(tt.args.s)
			if err != nil {
				t.Log(err)
				assert.Equal(t, true, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				assert.Equal(t, len(got), len(tt.want))
				if len(got) > 0 {
					sort.Slice(got, func(i, j int) bool {
						return got[i].HostPort < got[j].HostPort
					})
					assert.Equal(
						t,
						got[len(got)-1].HostPort-got[0].HostPort,
						got[len(got)-1].ContainerPort-got[0].ContainerPort,
					)
					for i := range len(got) {
						assert.Equal(t, got[i].ContainerPort, tt.want[i].ContainerPort)
						assert.Equal(t, got[i].Protocol, tt.want[i].Protocol)
						assert.Equal(t, got[i].HostIP, tt.want[i].HostIP)
					}
				}
			}
		})
	}
}

func TestParsePortsLabel(t *testing.T) {
	tests := []struct {
		name     string
		labelMap map[string]string
		want     []cni.PortMapping
		wantErr  bool
	}{
		{
			name: "normal",
			labelMap: map[string]string{
				labels.Ports: "[{\"HostPort\":12345,\"ContainerPort\":10000,\"Protocol\":\"tcp\",\"HostIP\":\"0.0.0.0\"}]",
			},
			want: []cni.PortMapping{
				{
					HostPort:      12345,
					ContainerPort: 10000,
					Protocol:      "tcp",
					HostIP:        "0.0.0.0",
				},
			},
			wantErr: false,
		},
		{
			name: "empty ports (value empty)",
			labelMap: map[string]string{
				labels.Ports: "",
			},
			want:    []cni.PortMapping{},
			wantErr: false,
		},
		{
			name:     "empty ports (key not exists)",
			labelMap: map[string]string{},
			want:     []cni.PortMapping{},
			wantErr:  false,
		},
		{
			name: "parse error (wrong format)",
			labelMap: map[string]string{
				labels.Ports: "{\"HostPort\":12345,\"ContainerPort\":10000,\"Protocol\":\"tcp\",\"HostIP\":\"0.0.0.0\"}",
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePortsLabel(tt.labelMap)
			if err != nil {
				t.Log(err)
				assert.Equal(t, true, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				assert.Equal(t, len(got), len(tt.want))
				if len(got) > 0 {
					sort.Slice(got, func(i, j int) bool {
						return got[i].HostPort < got[j].HostPort
					})
					assert.Equal(
						t,
						got[len(got)-1].HostPort-got[0].HostPort,
						got[len(got)-1].ContainerPort-got[0].ContainerPort,
					)
					for i := range len(got) {
						assert.Equal(t, got[i].HostPort, tt.want[i].HostPort)
						assert.Equal(t, got[i].ContainerPort, tt.want[i].ContainerPort)
						assert.Equal(t, got[i].Protocol, tt.want[i].Protocol)
						assert.Equal(t, got[i].HostIP, tt.want[i].HostIP)
					}
				}
			}
		})
	}
}

func TestParseFlagP(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name    string
		args    args
		want    []cni.PortMapping
		wantErr bool
	}{
		{
			name: "normal",
			args: args{
				s: "127.0.0.1:3000:8080/tcp",
			},
			want: []cni.PortMapping{
				{
					HostPort:      3000,
					ContainerPort: 8080,
					Protocol:      "tcp",
					HostIP:        "127.0.0.1",
				},
			},
			wantErr: false,
		},
		{
			name: "with port range",
			args: args{
				s: "127.0.0.1:3000-3001:8080-8081/tcp",
			},
			want: []cni.PortMapping{
				{
					HostPort:      3000,
					ContainerPort: 8080,
					Protocol:      "tcp",
					HostIP:        "127.0.0.1",
				},
				{
					HostPort:      3001,
					ContainerPort: 8081,
					Protocol:      "tcp",
					HostIP:        "127.0.0.1",
				},
			},
			wantErr: false,
		},
		{
			name: "with wrong port range",
			args: args{
				s: "127.0.0.1:3000-3001:8080-8082/tcp",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "without host ip",
			args: args{
				s: "3000:8080/tcp",
			},
			want: []cni.PortMapping{
				{
					HostPort:      3000,
					ContainerPort: 8080,
					Protocol:      "tcp",
					HostIP:        "0.0.0.0",
				},
			},
			wantErr: false,
		},
		{
			name: "without protocol",
			args: args{
				s: "3000:8080",
			},
			want: []cni.PortMapping{
				{
					HostPort:      3000,
					ContainerPort: 8080,
					Protocol:      "tcp",
					HostIP:        "0.0.0.0",
				},
			},
			wantErr: false,
		},
		{
			name: "with protocol udp",
			args: args{
				s: "3000:8080/udp",
			},
			want: []cni.PortMapping{
				{
					HostPort:      3000,
					ContainerPort: 8080,
					Protocol:      "udp",
					HostIP:        "0.0.0.0",
				},
			},
			wantErr: false,
		},
		{
			name: "with protocol udp",
			args: args{
				s: "3000:8080/sctp",
			},
			want: []cni.PortMapping{
				{
					HostPort:      3000,
					ContainerPort: 8080,
					Protocol:      "sctp",
					HostIP:        "0.0.0.0",
				},
			},
			wantErr: false,
		},
		{
			name: "with ipv6 host ip",
			args: args{
				s: "[::0]:8080:80/tcp",
			},
			want: []cni.PortMapping{
				{
					HostPort:      8080,
					ContainerPort: 80,
					Protocol:      "tcp",
					HostIP:        "::0",
				},
			},
			wantErr: false,
		},
		{
			name: "with invalid protocol",
			args: args{
				s: "3000:8080/invalid",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "multiple colon",
			args: args{
				s: "127.0.0.1:3000:0.0.0.0:8080",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "multiple slash",
			args: args{
				s: "127.0.0.1:3000:8080/tcp/",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "invalid ip",
			args: args{
				s: "127.0.0.256:3000:8080/tcp",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "large port",
			args: args{
				s: "3000:65536",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "blank",
			args: args{
				s: "",
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseFlagP(tt.args.s)
			t.Log(err)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseFlagP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				if len(got) == len(tt.want) {
					if len(got) > 1 {
						var hostPorts []int32
						var containerPorts []int32
						for _, value := range got {
							hostPorts = append(hostPorts, value.HostPort)
							containerPorts = append(containerPorts, value.ContainerPort)
						}
						sort.Slice(hostPorts, func(i, j int) bool {
							return i < j
						})
						sort.Slice(containerPorts, func(i, j int) bool {
							return i < j
						})
						if (hostPorts[len(hostPorts)-1] - hostPorts[0]) != (containerPorts[len(hostPorts)-1] - containerPorts[0]) {
							t.Errorf("ParseFlagP() = %v, want %v", got, tt.want)
						}
					}
				} else {
					t.Errorf("ParseFlagP() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
