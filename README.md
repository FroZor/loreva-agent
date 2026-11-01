# Loreva Agent

Loreva Agent runs on a Linux server and lets Loreva App manage it.

- **Direct access** (default): the app connects straight to the server over one TCP port. TLS 1.3 with post-quantum key exchange, both sides pin each other's key. No account or Loreva service needed.
- **Portal**: the agent keeps an outbound connection to a Loreva portal, so no inbound port is needed.
- Both modes can run together and speak the same protocol: node info, hardware and network reports, live metrics, OCI, Compose, Dockerfile and Pterodactyl Egg workloads.
- Linux is the supported node platform. macOS and Windows builds exist but are not supported for nodes.
- The agent never changes the firewall, network interfaces or routes.

## Install

Linux (systemd):

```sh
curl -fsSLO https://raw.githubusercontent.com/FroZor/loreva-agent/master/install.sh && sudo sh install.sh
```

Docker Compose:

```sh
curl -fsSLO https://raw.githubusercontent.com/FroZor/loreva-agent/master/compose.yaml && docker compose up -d
```

macOS and Windows: download the binary for your platform and `checksums.txt` from [Releases](https://github.com/FroZor/loreva-agent/releases/latest), check the SHA-256, then run `loreva-agent configure` and `loreva-agent run` (foreground only).

## Connect a device

- The installer prints a connection key `loreva://connect/...`. Paste it into Loreva App.
- Check that the code in the app (for example `ABCD-EFGH`) matches the server, then answer `y`.
- If inbound traffic is filtered, allow the TCP port the installer printed.
- Docker: get a key with `docker compose exec loreva-agent /loreva-agent invite`.

Later:

| Command | Purpose |
| --- | --- |
| `sudo loreva-agent invite` | New connection key for another device. Also restores access when no device is left. |
| `sudo loreva-agent devices` | List paired devices. |
| `sudo loreva-agent devices remove ID` | Revoke a device. |

A key is single-use, expires after 15 minutes (`--ttl`, at most 1h) and works only while `invite` is running. Behind NAT add the public address with `--endpoint 203.0.113.10`.

## Portal mode

- Linux: `sudo sh install.sh --portal` and paste the portal bootstrap.
- Docker: `docker compose run --rm loreva-agent configure`, or mount the bootstrap at `/run/secrets/bootstrap.json` before the first start.
- Manual JSON: `loreva-agent enroll --config config.json`, see [config.example.jsonc](config.example.jsonc) (strict JSON, no comments).
- To replace a connected identity: `disconnect`, then `configure`, then `connect`. The old identity stays until the new one is committed.
- To add direct access to an enrolled node: `sudo loreva-agent init`, then `sudo systemctl restart loreva-agent`.

## Commands

| Command | Purpose |
| --- | --- |
| `init` | Create the node identity for direct access. |
| `invite` | Print a connection key and approve the device that uses it. |
| `devices`, `devices remove ID` | List or revoke paired devices. |
| `device pair`, `device connect` | Reference test client. |
| `configure` | Enroll with a portal bootstrap. |
| `enroll --config FILE` | Enroll with a JSON file. |
| `disconnect`, `connect` | Close or restore the portal connection, keeping the identity. |
| `status` | Show state, node ID and portal. |
| `run` | Run with the existing identity (default). |
| `start --config FILE` | Enroll if needed, then run (container image). |
| `version` | Print the version. |

## Docker notes

- Uses the host network, PID and hostname namespaces and mounts the host root read-only at `/host`, so it reports on the host, not the container.
- Gets the Docker socket to manage workloads. Runs as root with all capabilities dropped except `NET_ADMIN`, `SYS_CHROOT` and `CHOWN`, like the systemd service.
- Host `/root`, `/home` and `/etc/shadow` are hidden.
- State lives in the `loreva-agent-state` volume.
- The image tracks `latest`. Pin the tag in `compose.yaml` to control upgrades.
- Docker Desktop: use Linux containers and remove the `rslave` line.

## State

| Runtime | Location |
| --- | --- |
| Linux systemd | `/var/lib/loreva-agent` |
| Linux user | `~/.config/loreva-agent` (or `$XDG_CONFIG_HOME`) |
| macOS | `~/Library/Application Support/loreva-agent` |
| Windows | `%AppData%\loreva-agent` |
| Docker | `loreva-agent-state` volume |

Override with `--state-dir` or `LOREVA_STATE_DIR`.

## Uninstall

- Linux: `sudo systemctl disable --now loreva-agent && sudo rm -f /etc/systemd/system/loreva-agent.service /usr/local/bin/loreva-agent && sudo systemctl daemon-reload`
- Docker: `docker compose down --rmi all`
- macOS, Windows: stop the process and delete the binary.
- This keeps the identity and paired devices. To remove the node for good, remove it in the portal first, then delete the state directory or the Docker volume.

## Development

- Requires Go 1.26.10.
- Test and build: `go test ./... && go build -trimpath -o loreva-agent ./cmd/loreva-agent`
- Local portal: `go run ./cmd/loreva-agent configure`, then `go run ./cmd/loreva-agent`.
- Protocol: [contract/v1](contract/v1/README.md), checked against the Go types by `go test`.
- Release: push an annotated tag `vX.Y.Z`. CI publishes Linux, macOS and Windows binaries, checksums and a Linux image.
