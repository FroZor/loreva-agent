module github.com/FroZor/loreva-agent

go 1.26.6

require (
	github.com/cloudflare/circl v1.6.5
	github.com/coder/websocket v1.8.15
)

// Security override for GO-2026-5024 / CVE-2026-39824.
require golang.org/x/sys v0.47.0
