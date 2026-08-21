module github.com/FroZor/loreva-agent

go 1.26.6

require (
	github.com/cloudflare/circl v1.6.5
	github.com/coder/websocket v1.8.15
	github.com/shirou/gopsutil/v4 v4.26.7
	golang.org/x/term v0.45.0
)

require (
	github.com/ebitengine/purego v0.10.2 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/power-devops/perfstat v0.0.0-20240221224432-82ca36839d55 // indirect
	github.com/tklauser/go-sysconf v0.3.16 // indirect
	github.com/tklauser/numcpus v0.11.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
)

// Security override for GO-2026-5024 / CVE-2026-39824.
require golang.org/x/sys v0.47.0
