package containerinfo

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"

	"github.com/FroZor/loreva-agent/internal/containerio"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

var testID = strings.Repeat("ab", 32)

type fakeEngine struct {
	containers []container.Summary
	inspect    client.ContainerInspectResult
	inspectErr error
	imageErr   error
	listAll    bool
}

func (f *fakeEngine) Info(context.Context, client.InfoOptions) (client.SystemInfoResult, error) {
	return client.SystemInfoResult{}, nil
}

func (f *fakeEngine) ContainerList(_ context.Context, options client.ContainerListOptions) (client.ContainerListResult, error) {
	f.listAll = options.All
	return client.ContainerListResult{Items: f.containers}, nil
}

func (f *fakeEngine) ContainerInspect(context.Context, string, client.ContainerInspectOptions) (client.ContainerInspectResult, error) {
	return f.inspect, f.inspectErr
}

func (f *fakeEngine) ImageInspect(context.Context, string, ...client.ImageInspectOption) (client.ImageInspectResult, error) {
	return client.ImageInspectResult{}, f.imageErr
}

func TestListIncludesStoppedContainersSortedByName(t *testing.T) {
	engine := &fakeEngine{containers: []container.Summary{
		{ID: testID, Names: []string{"/web"}, State: "running", Health: &container.HealthSummary{Status: "healthy"}},
		{ID: testID, Names: []string{"/backup"}, State: "exited", Labels: map[string]string{labelComposeProject: "ops"}},
	}}

	result, err := New(engine).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if !engine.listAll {
		t.Fatal("stopped containers were not asked for")
	}
	if len(result.Items) != 2 || result.Items[0].Name != "backup" || result.Items[1].Health != "healthy" || result.Items[0].Health != "none" {
		t.Fatalf("items = %+v", result.Items)
	}
	if result.Items[0].ComposeProject != "ops" || result.Engine.Runtime != "docker" || result.Engine.Warnings == nil {
		t.Fatalf("result = %+v", result)
	}
}

func TestInspectReportsPublishedAndExposedPorts(t *testing.T) {
	published := network.MustParsePort("25565/tcp")
	exposed := network.MustParsePort("25575/tcp")
	engine := &fakeEngine{
		imageErr: errors.New("image removed"),
		inspect: client.ContainerInspectResult{Container: container.InspectResponse{
			ID:    testID,
			Name:  "/minecraft",
			Image: "sha256:abc",
			State: &container.State{Status: "running", Running: true, StartedAt: "2026-10-06T10:00:00Z", FinishedAt: "0001-01-01T00:00:00Z"},
			Config: &container.Config{
				ExposedPorts: network.PortSet{published: {}, exposed: {}},
				Env:          []string{"RCON_PASSWORD=secret"},
				Labels:       map[string]string{labelComposeProject: "games", labelComposeConfigFiles: "/srv/a.yaml,/srv/b.yaml"},
			},
			HostConfig: &container.HostConfig{NetworkMode: "bridge"},
			NetworkSettings: &container.NetworkSettings{Ports: network.PortMap{
				published: {{HostIP: netip.MustParseAddr("0.0.0.0"), HostPort: "25565"}},
			}},
		}},
	}

	details, err := New(engine).Inspect(context.Background(), testID, false)
	if err != nil {
		t.Fatal(err)
	}

	want := []protocol.ContainerPort{
		{ContainerPort: 25565, Protocol: "tcp", HostIP: "0.0.0.0", HostPort: 25565},
		{ContainerPort: 25575, Protocol: "tcp"},
	}
	if !slices.Equal(details.Ports, want) {
		t.Fatalf("ports = %+v", details.Ports)
	}
	if details.Name != "minecraft" || details.Image.Reference != "sha256:abc" || details.State.StartedAt == nil || details.State.FinishedAt != nil {
		t.Fatalf("details = %+v", details)
	}
	if details.Compose == nil || !slices.Equal(details.Compose.ConfigFiles, []string{"/srv/a.yaml", "/srv/b.yaml"}) {
		t.Fatalf("compose = %+v", details.Compose)
	}
	if !slices.Equal(details.Env, []string{"RCON_PASSWORD=secret"}) {
		t.Fatalf("env = %q", details.Env)
	}
}

func TestInspectErrors(t *testing.T) {
	if _, err := New(&fakeEngine{}).Inspect(context.Background(), "web", false); !errors.Is(err, containerio.ErrInvalidContainerID) {
		t.Fatalf("short ID error = %v", err)
	}

	engine := &fakeEngine{inspectErr: errdefs.ErrNotFound}
	if _, err := New(engine).Inspect(context.Background(), testID, false); !errors.Is(err, containerio.ErrNotFound) {
		t.Fatalf("missing container error = %v", err)
	}
}

func TestTruncateKeepsCharactersWhole(t *testing.T) {
	if got := truncate("abé", 3); got != "ab" {
		t.Fatalf("truncate = %q", got)
	}
	if got := truncate("a\xffb", 10); got != "a�b" {
		t.Fatalf("invalid UTF-8 = %q", got)
	}
}
