# Loreva Agent

Cross-platform node agent that maintains an outbound WSS connection to a Loreva portal. It handles enrollment, gateway failover, identity renewal, system and network reporting, one-second metrics, and portal-controlled OCI, Docker Compose, Dockerfile, and Pterodactyl Egg workloads.

## Requirements

- Go 1.26.6 for local development and source builds.
- A bootstrap issued by a Loreva portal.
- Docker Engine for workload management.
- Docker Compose plugin for Compose workloads and container installation.

## Build

### Unix

```sh
go mod verify
go test ./...
go build -trimpath -o loreva-agent ./cmd/loreva-agent
```

### Windows PowerShell

```powershell
go mod verify
go test ./...
go build -trimpath -o loreva-agent.exe ./cmd/loreva-agent
```

## Protocol contract

The repository-local [WSS protocol v1](contract/v1/protocol.schema.json) defines every agent/portal JSON frame. Contract compilation, message types, required fields, and canonical Go payloads are verified by `go test ./...`; the schema is not exposed by a runtime HTTP endpoint.

## Installation

### Linux

```sh
curl -fsSL https://raw.githubusercontent.com/FroZor/loreva-agent/master/install.sh -o install.sh
chmod +x install.sh
sudo ./install.sh
```

On systemd hosts, the installer verifies and installs the latest binary, prompts for the portal bootstrap, enrolls the node, and starts `loreva-agent.service`. Without systemd, it installs only `/usr/local/bin/loreva-agent`.

### macOS portable binary

```sh
case "$(uname -m)" in
  x86_64) ARCH=amd64 ;;
  arm64) ARCH=arm64 ;;
  *) echo "Unsupported architecture" >&2; exit 1 ;;
esac

ASSET="loreva-agent-darwin-${ARCH}"
curl -fsSLO "https://github.com/FroZor/loreva-agent/releases/latest/download/${ASSET}"
curl -fsSLO https://github.com/FroZor/loreva-agent/releases/latest/download/checksums.txt
grep "  ${ASSET}$" checksums.txt | shasum -a 256 -c -
sudo install -d -m 0755 /usr/local/bin
sudo install -m 0755 "${ASSET}" /usr/local/bin/loreva-agent
loreva-agent configure
loreva-agent run
```

### Windows portable binary

```powershell
$osArch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
$arch = switch ($osArch) {
    "X64" { "amd64" }
    "Arm64" { "arm64" }
    default { throw "Unsupported architecture: $osArch" }
}

$asset = "loreva-agent-windows-$arch.exe"
Invoke-WebRequest "https://github.com/FroZor/loreva-agent/releases/latest/download/$asset" -OutFile .\loreva-agent.exe
Invoke-WebRequest "https://github.com/FroZor/loreva-agent/releases/latest/download/checksums.txt" -OutFile .\checksums.txt

$pattern = "^[0-9a-fA-F]{64}\s+$([regex]::Escape($asset))$"
$line = Get-Content .\checksums.txt | Where-Object { $_ -match $pattern } | Select-Object -First 1
if (!$line) { throw "Checksum is missing for $asset" }

$expected = ($line -split '\s+')[0].ToLowerInvariant()
$actual = (Get-FileHash .\loreva-agent.exe -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw "Checksum verification failed" }

.\loreva-agent.exe configure
.\loreva-agent.exe run
```

The macOS and Windows binaries run in the foreground. Native service installation and platform code signing are not provided yet.

### Docker Compose

Unix:

```sh
curl -fsSLO https://raw.githubusercontent.com/FroZor/loreva-agent/master/compose.yaml
docker compose run --rm loreva-agent configure
docker compose up -d
```

Windows PowerShell:

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/FroZor/loreva-agent/master/compose.yaml -OutFile .\compose.yaml
docker compose run --rm loreva-agent configure
docker compose up -d
```

`configure` prompts for the portal-issued bootstrap. Docker Desktop on Windows must use Linux containers. State is stored in the `loreva-agent-state` volume; no inbound port is published. The agent container includes the official Docker CLI and Compose plugin and receives the Docker socket required to manage node workloads.

The bundled Compose file tracks `latest` and pulls it on every recreate. Pin the image tag in `compose.yaml` when upgrades must be controlled.

## Configuration

Portal bootstrap:

```sh
loreva-agent configure
```

Manual JSON enrollment:

```json
{
  "portal_url": "wss://portal.example.com:27460",
  "enrollment_token": "0123456789abcdef.replace-with-secret"
}
```

```sh
loreva-agent enroll --config config.json
loreva-agent run
```

See [config.example.jsonc](config.example.jsonc) for every supported field. The agent accepts strict JSON; comments are not allowed in the supplied configuration file.

## Local development

Configure the local portal to issue `wss://localhost:27460` as the agent endpoint:

```env
LOREVA_URL=http://localhost:27450
LOREVA_AGENT_PORT=27460
```

Restart the portal, create a new enrollment token, and run:

Unix:

```sh
go run ./cmd/loreva-agent configure
go run ./cmd/loreva-agent
```

Windows PowerShell:

```powershell
go run ./cmd/loreva-agent configure
go run ./cmd/loreva-agent
```

After enrollment, run the `./cmd/loreva-agent` package from the IDE without arguments. Use `localhost`, not `host.docker.internal`, when the portal and agent both run directly on Windows.

## Commands

| Command | Purpose |
| --- | --- |
| `configure` | Enroll or safely replace the current identity using a portal-issued bootstrap. |
| `disconnect` | Close the portal connection while preserving the identity. |
| `connect` | Allow the agent process to restore the portal connection. |
| `status` | Show the local lifecycle state, node ID, and portal. |
| `enroll --config FILE` | Enroll using manual JSON configuration. |
| `run` | Connect using an existing identity. This is also the default command. |
| `start --config FILE` | Enroll when identity is missing, then run. Used by the container image. |
| `version` | Print the agent version. |

`configure` never overwrites an identity that is in use. Disconnect first when replacing a connected node:

```sh
loreva-agent disconnect
loreva-agent configure
loreva-agent connect
```

The previous identity remains intact until the replacement enrollment is fully validated and committed.

## State

| Runtime | Default state location |
| --- | --- |
| Linux user | `$XDG_CONFIG_HOME/loreva-agent` or `~/.config/loreva-agent` |
| Linux systemd installer | `/var/lib/loreva-agent` |
| macOS | `~/Library/Application Support/loreva-agent` |
| Windows | `%AppData%\loreva-agent` |
| Docker Compose | `loreva-agent-state` volume |

Override the location with `--state-dir` or `LOREVA_STATE_DIR`.

## Release

Create and push an annotated `vMAJOR.MINOR.PATCH` tag:

```sh
VERSION=vX.Y.Z
git tag -a "$VERSION" -m "Release $VERSION"
git push origin "$VERSION"
```

The workflow publishes AMD64 and ARM64 binaries for Linux, macOS, and Windows, SHA-256 checksums, and a multi-platform Linux image.

## Uninstall

Linux systemd installation:

```sh
sudo systemctl disable --now loreva-agent
sudo rm -f /etc/systemd/system/loreva-agent.service /usr/local/bin/loreva-agent
sudo systemctl daemon-reload
```

Docker Compose installation:

```sh
docker compose down --rmi all
```

For macOS or Windows, stop the foreground process and remove the binary. These commands preserve the enrolled identity. Revoke the node in the portal before intentionally removing its state directory or Docker volume.
