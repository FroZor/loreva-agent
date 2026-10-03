# Loreva Agent

Loreva Agent runs on a Linux server (VPS, VDS, or bare metal) and lets Loreva App manage it. It works in two modes, which can run together:

- **Direct access** (default): the app connects straight to the node over WireGuard, with no account and no Loreva service in between. The agent runs WireGuard in userspace, so it adds no network interface, route, or firewall rule; it opens one UDP port and no TCP port.
- **Portal**: the agent keeps an outbound WSS connection to a public or self-hosted Loreva portal, so the node needs no inbound port at all.

The current milestone implements direct access (setup, pairing, and a read-only API for node information, hardware, and network), plus portal enrollment, connectivity, gateway failover, and identity renewal. Container management is not implemented yet.

Linux is the supported node platform. Windows and macOS builds are published but are not supported for nodes.

Documentation:

- [docs/api/openapi.yaml](docs/api/openapi.yaml): the HTTP API that the agent serves to paired devices.
- [docs/protocol.md](docs/protocol.md): the connection key format, pairing, WireGuard settings, the local control socket, and the portal protocol.

## Quick start

On the server:

```sh
curl -fsSL https://raw.githubusercontent.com/FroZor/loreva-agent/master/install.sh -o install.sh
chmod +x install.sh && sudo ./install.sh
```

The installer verifies the release checksum, creates the `loreva-agent` system user, initializes the node, starts the service, and prints a single-use connection key (`loreva1:...`). Paste the key into Loreva App. When the app shows a code such as `ABCD-EFGH`, check that the server shows the same code and answer `y`.

If inbound UDP is filtered, allow the UDP port printed by the installer. The agent never changes the firewall.

To connect another device later:

```sh
sudo loreva-agent invite            # print a new connection key and approve the device
sudo loreva-agent devices           # list paired devices
sudo loreva-agent devices remove ID # revoke a device
```

`invite` also restores access when no paired device is left. A connection key expires after 15 minutes (`--ttl`, at most 1h) and works only while `invite` keeps running. If the server's public address is not on one of its interfaces (for example behind NAT), add it with `--endpoint 203.0.113.10` or set it once with `init --endpoint`.

### Command-line client

The binary includes a reference client that is useful for testing and scripts:

```sh
loreva-agent device pair --credentials my-server.json --name laptop   # paste the connection key
loreva-agent device call --credentials my-server.json /v1/node
```

The credentials file holds the device's WireGuard key and is created with mode 0600.

## Build

Version tags are built by [GitHub Actions](.github/workflows/release.yml). The pipeline verifies modules, runs tests, `go vet`, and `govulncheck`, then publishes binaries, checksums, and a multi-platform container image. Installation does not require a local compiler.

## Release

Push a stable SemVer tag to start the release workflow:

```sh
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

Release tags must use the exact `vMAJOR.MINOR.PATCH` format.

## Portal installation

### Binary

Run the installer with `--portal` and paste the portal bootstrap when prompted:

```sh
sudo ./install.sh --portal
```

The installer detects AMD64 or ARM64, verifies the release checksum, enrolls the node, and starts a systemd service.
Self-hosted distributions only need to override `LOREVA_DOWNLOAD_BASE_URL` and, when required, `LOREVA_INSTALL_PATH`.

To add direct access to a node that is already enrolled, initialize it as the service user and restart the service:

```sh
sudo -u loreva-agent loreva-agent init --state-dir /var/lib/loreva-agent
sudo systemctl restart loreva-agent
```

### Docker

Download Compose, paste the portal bootstrap when prompted, and start the agent:

```sh
curl -fsSLO https://raw.githubusercontent.com/FroZor/loreva-agent/master/compose.yaml
docker compose run --rm loreva-agent configure && docker compose up -d
```

Enrollment stores the node identity in the Compose volume. The long-running container receives neither the bootstrap nor an enrollment token, and no ports are published. The Docker image currently supports portal mode only.

## Minimal configuration

Manual enrollment accepts strict JSON:

```json
{
  "portal_url": "wss://portal.example.com:27460",
  "enrollment_token": "0123456789abcdef.replace-with-secret"
}
```

The token must be obtained from the portal through an authenticated channel. `portal_ca` is additionally required when the portal certificate is not trusted by the operating system; the portal supplies its ML-DSA root during enrollment.

See [config.example.jsonc](config.example.jsonc) for every supported setting with comments. The example is documentation: remove its comments and replace its placeholders before passing it to `enroll --config`, because the agent accepts strict JSON only.

To use a manual `config.json` during installation, replace the enrollment command with `sudo ./install.sh --config config.json` for the binary, or `docker compose run --rm -T loreva-agent enroll --config - < config.json && docker compose up -d` for Docker.

## Uninstallation

There is no built-in uninstall command. Stop the agent first, then remove the installed binary or container.

Binary installation:

```sh
sudo systemctl disable --now loreva-agent
sudo rm -f /etc/systemd/system/loreva-agent.service /usr/local/bin/loreva-agent
sudo systemctl daemon-reload
```

Docker installation:

```sh
docker compose down --rmi all
```

These steps intentionally preserve the node identity and paired devices in `/var/lib/loreva-agent`. For permanent removal, first revoke or remove the node in the portal, then delete the exact state directory used by the binary or remove the Docker volume with `docker volume rm loreva-agent-state`. Deleting local state alone does not remove the node from the portal.
