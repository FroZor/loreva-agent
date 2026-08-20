# Loreva Agent

Loreva Agent is a cross-platform node agent designed to manage container workloads and collect host telemetry. Like an edge agent, it establishes an outbound WSS connection to a public or self-hosted portal, so the node does not require an inbound control port.

The current development milestone implements enrollment, authenticated connectivity, gateway failover, and identity renewal. Container operations and telemetry delivery are not connected to the portal session yet.

## Build

Version tags are built by [GitHub Actions](.github/workflows/release.yml). The pipeline verifies modules, runs tests, `go vet`, and `govulncheck`, then publishes binaries, checksums, and a multi-platform container image. Installation does not require a local compiler.

## Release

Push a stable SemVer tag to start the release workflow:

```sh
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

Release tags must use the exact `vMAJOR.MINOR.PATCH` format.

## Installation

### Binary

Run the installer and paste the portal bootstrap when prompted:

```sh
curl -fsSL https://raw.githubusercontent.com/FroZor/loreva-agent/master/install.sh -o install.sh
chmod +x install.sh && sudo ./install.sh
```

The installer detects AMD64 or ARM64, verifies the release checksum, enrolls the node, and starts a systemd service.
Self-hosted distributions only need to override `LOREVA_DOWNLOAD_BASE_URL` and, when required, `LOREVA_INSTALL_PATH`.

### Docker

Download Compose, paste the portal bootstrap when prompted, and start the agent:

```sh
curl -fsSLO https://raw.githubusercontent.com/FroZor/loreva-agent/master/compose.yaml
docker compose run --rm loreva-agent configure && docker compose up -d
```

Enrollment stores the node identity in the Compose volume. The long-running container receives neither the bootstrap nor an enrollment token, and no ports are published.

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

These steps intentionally preserve the enrolled identity. For permanent removal, first revoke or remove the node in the portal, then delete the exact state directory used by the binary or remove the Docker volume with `docker volume rm loreva-agent-state`. Deleting local state alone does not remove the node from the portal.
