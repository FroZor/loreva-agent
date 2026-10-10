module github.com/FroZor/loreva-agent

go 1.26.9

require (
	github.com/cloudflare/circl v1.6.5
	github.com/coder/websocket v1.8.15
	github.com/compose-spec/compose-go/v2 v2.14.0
	github.com/containerd/errdefs v1.0.0
	github.com/distribution/reference v0.6.0
	github.com/moby/moby/api v1.55.0
	github.com/moby/moby/client v0.5.1
	github.com/opencontainers/go-digest v1.0.0
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.3
	github.com/shirou/gopsutil/v4 v4.26.7
	go.yaml.in/yaml/v4 v4.0.0-rc.6
	golang.org/x/net v0.60.0
	golang.org/x/term v0.46.0
)

require (
	github.com/Microsoft/go-winio v0.6.3-0.20251027160822-ad3df93bed29 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/docker/go-connections v0.7.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/ebitengine/purego v0.10.2 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mattn/go-shellwords v1.0.14 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/power-devops/perfstat v0.0.0-20240221224432-82ca36839d55 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/tklauser/go-sysconf v0.3.16 // indirect
	github.com/tklauser/numcpus v0.11.0 // indirect
	github.com/xhit/go-str2duration/v2 v2.1.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.69.0 // indirect
	go.opentelemetry.io/otel v1.44.0 // indirect
	go.opentelemetry.io/otel/metric v1.44.0 // indirect
	go.opentelemetry.io/otel/trace v1.44.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)

// Security override for GO-2026-5024 / CVE-2026-39824.
require golang.org/x/sys v0.48.0
