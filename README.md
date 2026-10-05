# Loreva Agent

Loreva Agent runs on a Linux server (VPS, VDS, or bare metal) and lets Loreva App manage it. It works in two modes, which can run together:

- **Direct access** (default): the app connects straight to the node, with no account and no Loreva service in between. The agent listens on one TCP port (a free random port between 20000 and 32000, or `init --port`). Connections use TLS 1.3 with the hybrid post-quantum key exchange X25519MLKEM768 only, and both sides pin each other's key: the node accepts only the client certificates of paired devices, plus new keys while a pairing invite is active. The agent adds no network interface, route, or firewall rule.
- **Portal**: the agent keeps an outbound WSS connection to a public or self-hosted Loreva portal, so the node needs no inbound port at all.

Both modes speak the same protocol: node information, hardware and network reports, one-second metrics, and OCI, Docker Compose, Dockerfile, and Pterodactyl Egg workloads. They differ only in connectivity, that is, who opens the connection and how the peers authenticate. The portal mode also covers enrollment, gateway failover, and identity renewal.

Linux is the supported node platform. Windows and macOS builds are published but are not supported for nodes.

The protocol is specified in [contract/v1](contract/v1/README.md); a test keeps the JSON Schema in line with the Go types in `internal/protocol`. The connection key format and pairing are implemented in `internal/pairing`, and `internal/client` is the reference device client.

## Quick start

On the server:

```sh
curl -fsSL https://raw.githubusercontent.com/FroZor/loreva-agent/master/install.sh -o install.sh
chmod +x install.sh && sudo ./install.sh
```

The installer verifies the release checksum, creates the `loreva-agent` system user, initializes the node, starts the service, and prints a single-use connection key (`loreva://connect/...`). Paste the key into Loreva App. When the app shows a code such as `ABCD-EFGH`, check that the server shows the same code and answer `y`.

If inbound traffic is filtered, allow the TCP port printed by the installer. The agent never changes the firewall.

To connect another device later:

```sh
sudo loreva-agent invite            # print a new connection key and approve the device
sudo loreva-agent devices           # list paired devices
sudo loreva-agent devices remove ID # revoke a device
```

`invite` also restores access when no paired device is left. A connection key expires after 15 minutes (`--ttl`, at most 1h) and works only while `invite` keeps running. If the server's public address is not on one of its interfaces (for example behind NAT), add it with `--endpoint 203.0.113.10` or set it once with `init --endpoint`.

### Test client

The binary contains a reference device client for testing and scripts. Loreva App implements the same protocol itself.

```sh
loreva-agent device pair --credentials my-server.json --name laptop   # paste the connection key
loreva-agent device connect --credentials my-server.json               # node frames on stdout, your frames on stdin
```

The credentials file holds the device's TLS key and is created with mode 0600.

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

## Portal installation

### Linux

Run the installer with `--portal` and paste the portal bootstrap when prompted:

```sh
curl -fsSL https://raw.githubusercontent.com/FroZor/loreva-agent/master/install.sh -o install.sh
chmod +x install.sh
sudo ./install.sh --portal
```

On systemd hosts, the installer verifies and installs the latest binary, prompts for the portal bootstrap, enrolls the node, and starts `loreva-agent.service`. Without systemd, it installs only `/usr/local/bin/loreva-agent`.

To add direct access to a node that is already enrolled, initialize it as the service user and restart the service:

```sh
sudo -u loreva-agent loreva-agent init --state-dir /var/lib/loreva-agent
sudo systemctl restart loreva-agent
```

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

`configure` prompts for the portal-issued bootstrap. The Docker image currently supports portal mode only. Docker Desktop on Windows must use Linux containers. State is stored in the `loreva-agent-state` volume; no inbound port is published. The agent container includes the official Docker CLI and Compose plugin and receives the Docker socket required to manage node workloads.

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
| `init` | Create the node identity for direct access. |
| `invite` | Print a single-use connection key and approve the device that uses it. |
| `devices`, `devices remove ID` | List or revoke paired devices. |
| `device pair`, `device connect` | Reference device client for testing and scripts. |
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

For macOS or Windows, stop the foreground process and remove the binary. These steps intentionally preserve the node identity and paired devices. For permanent removal, first revoke or remove the node in the portal, then delete the exact state directory used by the binary or remove the Docker volume with `docker volume rm loreva-agent-state`. Deleting local state alone does not remove the node from the portal.
