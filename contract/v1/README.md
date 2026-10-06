# Loreva agent protocol v1

`protocol.schema.json` is the normative, repository-local contract for every JSON text frame the agent exchanges with a portal and with paired devices. There is one protocol; only the connectivity differs, that is, who opens the connection and how the peers authenticate:

| Endpoint | Opened by | WebSocket subprotocol | Authentication |
| --- | --- | --- | --- |
| `/agent/v1/enroll` on the portal | agent | `loreva.enrollment.v1` | Enrollment bearer token during Upgrade |
| `/agent/v1/connect` on the portal | agent | `loreva.connect.v1` | TLS 1.3 mTLS followed by ML-DSA proof |
| `wss://<node IP>:<port>/v1/session` on the node's direct access TCP port | device (Loreva App) | `loreva.session.v1` | TLS 1.3, X25519MLKEM768 only; mutual key pinning: the node key from the connection key, the device key from pairing |

The device session runs over TLS 1.3 on one TCP port that `loreva-agent init` picks (a free random port between 20000 and 32000) or that `init --port` sets. Both sides offer only the hybrid key exchange X25519MLKEM768 and check after the handshake that it was used, so there is no classical fallback. Certificates are self-signed and authenticated by pin: the standard Base64 SHA-256 of the certificate's SubjectPublicKeyInfo. Keys are ECDSA P-256 (Ed25519 is also accepted from devices). The node requires a client certificate on every connection and finishes the handshake only for the key of a paired device or, while a pairing invite is active, for a new key; every other client gets a TLS alert before any HTTP. Session tickets are disabled, so a revoked key cannot resume.

The schema is not published by an HTTP endpoint. `$schema` is only the JSON Schema dialect identifier; `$id` is a non-resolvable URN. All `$ref` values stay inside the file.

The non-frame definitions `agentKeyProofHeader`, `agentSessionProofHeader`, `portalJWSHeader`, `popClaims`, `pqCredentialClaims`, and `connectChallengeClaims` define the decoded Compact JWS structures carried by frame string fields.

## Message order

Enrollment:

```text
portal enrollment.challenge
agent  enrollment.request
portal enrollment.accepted | enrollment.rejected
```

Working connection:

```text
portal connect.challenge
agent  connect.proof
portal connect.accepted | connect.rejected
```

After `connect.accepted`, the agent can send `renew.request`, `node.specifications.report`, `node.network.report`, `metrics.report`, and `metrics.rollup` (see [Metrics store](#metrics-store)). A metrics frame contains `metric.type`: `node`, `container`, or a versioned `plugin:<name>` adapter namespace. The portal can send the correlated accepted/rejected responses, `sources.update`, `drain`, a signed `portal.command`, `metrics.query`, `node.network.refresh`, `node.process.inspect`, `containers.list`, `container.inspect`, and the container log and console requests of [Container logs and consoles](#container-logs-and-consoles).

## Workload commands

The WSS frame contains only a signed envelope:

```json
{
  "type": "portal.command",
  "signed_command": "<ML-DSA-65 Compact JWS>"
}
```

The JWS protected header is exactly `{"alg":"ML-DSA-65"}`. Its decoded payload uses the common command envelope:

```json
{
  "type": "workload.plan.request",
  "schema_version": 1,
  "request_id": "2ab9d734-7434-4cdf-bca4-6ce7a46cdd65",
  "portal_id": "d1b181c1-52ec-4d55-b2c9-b1428305b294",
  "node_id": "65a1876f-a715-45fc-9ac0-e4bc31067059",
  "workload_id": "6e0c1d91-5145-440f-bf97-d84db4f83644",
  "session_nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "issued_at": "2030-01-02T03:04:05Z",
  "expires_at": "2030-01-02T03:04:35Z",
  "payload": {
    "format": "compose",
    "compose": {
      "artifact": {
        "artifact_id": "df9ffacf-fd65-4643-967b-422b2d4c826c",
        "sha256": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "size_bytes": 841
      },
      "file": "compose.yaml",
      "environment": {
        "MINECRAFT_VERSION": "1.21.11"
      }
    }
  }
}
```

`format` is `oci`, `compose`, `dockerfile`, or `pterodactyl-egg`; the matching nested object is the only format-specific input. Compose and Dockerfile artifacts are bounded `tar.gz` files. Egg artifacts are strict `PTDL_v2` JSON. A Portainer App Template is resolved by the portal into its referenced OCI or Compose input before it reaches the agent; the agent never follows a template's arbitrary repository URL.

An Egg with an installation script also requires a digest-pinned installer selected from the image declared by the Egg:

```json
{
  "format": "pterodactyl-egg",
  "pterodactyl_egg": {
    "artifact": {
      "artifact_id": "df9ffacf-fd65-4643-967b-422b2d4c826c",
      "sha256": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "size_bytes": 841
    },
    "docker_image": "ghcr.io/ptero-eggs/yolks:java_21@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "installer_image": "ghcr.io/ptero-eggs/installers:alpine@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "variables": {
      "MINECRAFT_VERSION": "latest",
      "SERVER_JARFILE": "server.jar"
    },
    "agreements": ["minecraft_eula"],
    "resources": {
      "cpu_millicores": 2000,
      "memory_bytes": 2147483648,
      "pids_limit": 512
    },
    "ports": [
      {"host_ip": "", "host_port": 25565, "container_port": 25565, "protocol": "tcp"}
    ]
  }
}
```

The portal resolves both image tags to registry digests before signing the plan command. The agent verifies that the pinned name and tag are declared by the Egg; it never executes an unpinned installer image.

The agent downloads an artifact only from the enrolled portal:

```http
GET /agent/v1/artifacts/{artifact_id}
Accept: application/octet-stream
```

The request uses the node mTLS identity and the same PQ-hybrid TLS policy as `/connect`. Redirects are rejected. The response must be `200`, and its exact body must match the signed `size_bytes` and `sha256`.

Planning does not start containers. It returns stable steps, policy findings, and a digest:

```json
{
  "type": "workload.plan.result",
  "schema_version": 1,
  "request_id": "2ab9d734-7434-4cdf-bca4-6ce7a46cdd65",
  "portal_id": "d1b181c1-52ec-4d55-b2c9-b1428305b294",
  "node_id": "65a1876f-a715-45fc-9ac0-e4bc31067059",
  "workload_id": "6e0c1d91-5145-440f-bf97-d84db4f83644",
  "occurred_at": "2030-01-02T03:04:06Z",
  "payload": {
    "state": "ready",
    "plan_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "steps": [
      {"sequence": 1, "action": "load", "resource": "compose.yaml"},
      {"sequence": 2, "action": "pull", "resource": "compose.images"},
      {"sequence": 3, "action": "up", "resource": "loreva-6e0c1d915145440fbf97d84db4f83644"}
    ],
    "findings": []
  }
}
```

Execution is a second, independently signed command. `approvals` must contain every `finding_digest` whose `requires_approval` is true and may not contain unrelated digests:

```json
{
  "type": "workload.execute.request",
  "schema_version": 1,
  "request_id": "0d1b7f56-39b6-4b94-a3aa-c445a6a6ab59",
  "portal_id": "d1b181c1-52ec-4d55-b2c9-b1428305b294",
  "node_id": "65a1876f-a715-45fc-9ac0-e4bc31067059",
  "workload_id": "6e0c1d91-5145-440f-bf97-d84db4f83644",
  "session_nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "issued_at": "2030-01-02T03:04:10Z",
  "expires_at": "2030-01-02T03:04:40Z",
  "payload": {
    "plan_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "approvals": []
  }
}
```

The agent sends `workload.operation.event` while the operation runs and exactly one terminal `workload.operation.result`. Stop and restart use `{"timeout_seconds":30}`. Delete currently accepts only `{"data_policy":"preserve"}`; deleting persistent data needs a future, separately approved destructive contract.

## Device sessions

A device (Loreva App) reaches the node directly: the node cannot open a connection to an app on a user's computer, so the device always opens the session. The node's first frame is `session.hello`; its `peer` field is `invite` for a key that is being paired and `device` for a paired device.

### Connection key

The operator prints a single-use key with `sudo loreva-agent invite`:

```text
loreva://connect/<unpadded Base64URL of a JSON object>
```

The key is a URI, so the operating system can open Loreva App from it. The JSON object holds:

| Field | Meaning |
| --- | --- |
| `v` | Format version, `2` |
| `invite_id` | UUID of this invite |
| `node_id` | UUID of the node |
| `node_pin` | Pin of the node's TLS key; the device accepts only this key |
| `endpoints` | 1 to 16 `IP:port` addresses of the node's TCP port, tried in order |
| `token` | One-time pairing token, 32 bytes, unpadded Base64URL |
| `expires_at` | Expiry, RFC 3339 UTC; the node enforces it |

Whoever presents the token first can start pairing, so the key travels only over a channel the operator trusts; the code comparison below catches a token used by someone else. The token exists only in the memory of the agent and of the `invite` command.

### Pairing

```text
device generates a P-256 key and a self-signed certificate
device opens wss://<endpoint>/v1/session presenting that certificate, pinning node_pin
node   session.hello                 peer = invite
device pairing.request               device name, invite token
node   pairing.started               pairing ID, node nonce
       both sides show the same 8-character code; the operator approves on the node
node   pairing.result                approved (with device_id) | rejected | expired
```

The device proves it holds the new key in the TLS handshake, and commits to the key and its name before it learns the node's nonce. Both sides compute the code from the transcript:

```text
field(x) = uint32_be(len(x)) || x
th   = SHA-256(field("loreva.pairing.transcript.v2") || field(invite_id) || field(node_id) ||
               field(node_pin) || field(device_pin) || field(device_name) ||
               field(node_nonce, 32 bytes) || field(exporter, 32 bytes))
code = Base32(SHA-256("loreva.pairing.sas.v2" || th))[0:8], shown as XXXX-XXXX
```

`exporter` is the TLS exporter (RFC 8446 §7.5) of the pairing connection with the label `EXPORTER-loreva-pairing-v2`, no context, 32 bytes. It binds the code to that connection. A `pairing.request` with an unknown token is refused; one that fails validation otherwise is answered with `error` and does not use up the invite. Once the invite is used, the node again refuses unknown keys in the TLS handshake. A key that is not paired can send nothing but `pairing.request`. After approval the node stores the device key pin; the device keeps its key, its certificate, `node_pin`, and the endpoints.

### Working session

```text
device opens wss://<endpoint>/v1/session with its paired certificate
node   session.hello                 peer = device, device_id
node   node.specifications.report    device answers node.specifications.accepted | rejected
node   node.network.report           device answers node.network.accepted | rejected
node   metrics.rollup / metrics.report  stored history from the device's cursor, then live samples;
                                     device answers metrics.accepted | rejected, one frame at a time
```

Node reports and metrics are the same frames as on the portal session and follow the same rules: one report is outstanding at a time, a report is retried with the same `request_id` until it is acknowledged, and metrics start after both node reports. A device that stops acknowledging stops receiving metrics.

A device or the portal can also ask for stored history at any time with `metrics.query` (`from`, `to`, at most 8 days apart); the node answers `metrics.query.result` with the stored items in that range, oldest first, cut to one frame with `next_from` set when more remain.

A device sends requests at any time:

| Request | Answer |
| --- | --- |
| `workload.plan.request`, `workload.execute.request`, `workload.stop.request`, `workload.restart.request`, `workload.delete.request` | `workload.plan.result`, or `workload.operation.event` frames and one `workload.operation.result` |
| `artifact.upload.request` followed by `artifact.upload.chunk` frames | `artifact.upload.result` |
| `devices.list` | `devices.list.result` |
| `device.remove` | `device.remove.result`; the removed device's sessions end |
| `node.network.refresh` | a new `node.network.report`, see [Node network report](#node-network-report) |
| `node.process.inspect` | `node.process.inspect.result`, see [Metric units](#metric-units) |
| `containers.list`, `container.inspect` | `containers.list.result`, `container.inspect.result`, see [Containers](#containers) |
| `container.logs.open` | `container.logs.opened`, then binary stream frames and a final `stream.close` |
| `container.console.info` | `container.console.info.result` |
| `container.console.send` | `container.console.send.result` |

A request the node cannot accept is answered with `error`, which carries the request's `request_id` when it had a valid one.

A device workload request is the payload of a portal workload command without the portal envelope: `type`, `schema_version`, `request_id`, `workload_id`, and `payload`. It is not signed, because the TLS client certificate already authenticates the device. All devices of a node share one controller scope, the node ID, which the agent puts in `portal_id` of the command and of every result. Workloads created by devices are therefore separate from workloads created by a portal: a plan made by one controller cannot be executed, stopped, or deleted by the other.

The portal serves artifacts to the agent; a device uploads them before planning instead. `artifact.upload.request` announces the artifact (`artifact_id`, `sha256`, `size_bytes`, at most 32 MiB), then `artifact.upload.chunk` frames carry it in order: `offset` is the number of bytes sent so far and `data` is at most 32 KiB, standard Base64. After the last byte the node checks the size and the digest and answers `artifact.upload.result`. A session uploads one artifact at a time. A plan then references the artifact by the same `artifact_id`, `sha256`, and `size_bytes`.

Every paired device may use every operation. Revoking a device ends its open sessions, and the node refuses its key in the TLS handshake from then on.

### Containers

`containers.list` returns every container of the node's Docker, stopped ones included, sorted by name, at most 1024 (`truncated` is set when there are more). Each item has its ID, name, image, state, Docker's status line, `health` (`none` without a health check), creation time, ports, and the Compose project and service. `engine` describes Docker itself: version, storage, logging and cgroup drivers, cgroup version, default runtime, root directory, security options, container and image counts, and Docker's warnings. Metrics samples keep listing only running containers, because only they have resource usage.

`container.inspect` with a `container_id` returns what `docker inspect` shows an administrator:

- `image`: the reference the container was created with, the image ID, its registry digests (empty for local builds), creation time and size, and the `org.opencontainers.image.source` and `revision` labels that name where the image was built from.
- `command`: path and arguments of the main process, entrypoint, cmd, working directory, user, TTY and stdin settings, stop signal and timeout.
- `env` and `labels` in full, secrets included; masking them is the client's job.
- `state` with exit code, error, start and finish times, restart count, OOM kill, and the last health check result; `restart_policy` and `auto_remove`.
- `ports` (exposed ports without a host side are listed too), `network` (mode, hostname, DNS, extra hosts, and each attached network with its addresses and MAC), and `mounts`.
- `limits` (0 means not set), `security` (privileged, read-only root, added and dropped capabilities, security options, namespaces, devices, AppArmor profile), `logging`, and `compose` for containers created by Docker Compose.
- With `size: true` the node also measures the writable layer (`size_rw_bytes`) and the whole file system (`size_root_fs_bytes`); this can take a while on large containers.

Errors: `invalid_container_id`, `container_not_found`, `containers_unavailable` without Docker, `busy` when 4 container requests of the session are already running, and `too_large` when an answer would exceed 512 KiB. Strings longer than 32 KiB and lists or maps longer than 4096 entries are cut.

### Container logs and consoles

These requests work for any container on the node, named by its full 64-character Docker ID (`container_id` of the container metrics). The node serves them identically on a device session and on the portal session: whoever opened an authenticated session can send them, and only the authentication differs (the device's pinned TLS key, or the portal's mTLS and ML-DSA connect proof).

**Logs.** `container.logs.open` asks for a container's log: `tail` past lines (0 to 10000), optionally only entries after `since`, with `follow` to keep receiving new output and `timestamps` to prefix each line with Docker's RFC 3339 time. The device picks `stream_id` (1 to 2147483647, unique among its open streams; at most 8 streams are open per session). The node answers `container.logs.opened` with `tty`: when true the container has a terminal, stdout and stderr arrive merged, and the data may carry terminal control sequences such as colours. Docker serves logs only for the `local`, `json-file`, and `journald` logging drivers or with dual logging; otherwise the request fails with `error`.

The log data travels in binary WebSocket frames, without Base64:

```text
byte 0      channel: 1 = stdout (or the merged TTY output), 2 = stderr
bytes 1-4   stream_id, big-endian uint32
bytes 5-    1 to 32768 bytes of output
```

Flow control works per stream, as SSH channels and HTTP/2 streams do. The node may have at most 2 MiB (2097152 bytes) of data sent and not yet credited; it waits when that window is used up. The device returns credit with `stream.credit` (`bytes` 1 to 2097152) as it consumes data, usually the size of each frame it has processed; credit beyond the 2 MiB window is refused with `error` `invalid_credit`. A slow reader therefore pauses only its own stream; Docker keeps the log, and metrics and other frames keep flowing.

The node ends a stream with `stream.close`: `reason` `ended` when the log ended (the container stopped, or `follow` was false), or `failed` with a `code`. The device cancels a stream with `stream.close` `reason` `cancelled`; the node then stops and does not answer. Credit for an unknown or finished stream is ignored.

**Console.** `container.console.send` delivers one command line to the container's console and answers `container.console.send.result` with the `adapter` used and `output`, the console's reply. `container.console.info` tells which adapter a container offers, so the app shows the input line only where it works. The node picks the adapter from the container:

| Adapter | When | How |
| --- | --- | --- |
| `stdin` | The container was created with an open stdin (`docker run -i`, Compose `stdin_open: true`, Pterodactyl Eggs) and has no `dev.loreva.console` label, or the label is `stdin` | The node attaches to the container's stdin and writes the line. The server prints its reaction to its log, so `output` is empty; open a log stream to see it |
| `rcon` | Label `dev.loreva.console=rcon` | Source RCON (the protocol of Minecraft, ARK, Palworld, Counter-Strike, and others): the node authenticates and sends the command; `output` is the reply |
| `telnet` | Label `dev.loreva.console=telnet` | A line-based telnet console such as the one of 7 Days to Die: the node logs in, sends the command, and returns what the server printed until it was quiet for a second |
| `none` | No open stdin and no label, or `dev.loreva.console=none` | Commands are refused with `console_unavailable` |

For `rcon` and `telnet`, `dev.loreva.console.port` sets the port (defaults 25575 and 8081) and `dev.loreva.console.password_env` names the container environment variable that holds the password (default `RCON_PASSWORD` for RCON, none for telnet; RCON requires a password). The node connects to the container's own address on its Docker network, or to 127.0.0.1 for a container on the host network, so the console port does not need to be published. RCON and telnet are not encrypted; their traffic and the password stay on the node, and only the command and its reply cross the session.

A command is one line of 1 to 1024 bytes of UTF-8 text without control characters, so a frame cannot smuggle a second command after a line break. At most 20 commands per 10 seconds and 4 console or log-open requests in progress are accepted per session (`rate_limited`, `busy`). `output` is at most 8 KiB of text without control characters other than line feed and tab. The node writes every command to its log with the device or portal, the container, the adapter, and the first 256 bytes of the command.

Errors carry the request's `request_id` and one of these codes: `invalid_container_id`, `container_not_found`, `container_not_running`, `console_unavailable`, `console_misconfigured`, `console_unreachable`, `console_auth_failed`, `invalid_command`, `rate_limited`, `busy`, `containers_unavailable`, `invalid_stream_id`, `stream_id_in_use`, `too_many_streams`, `container_io_failed`.

### Files in container volumes

The file manager works inside one container, named by `container_id` like the log and console requests, and is served identically on device and portal sessions. It reaches the container's volumes and mounted folders, and nothing else: no file of the node, of another container, or of the container's image. Paths are absolute paths as the container sees them, such as `/data/server.properties`.

The node itself has no access to Docker's data. For each container with the file manager open it asks Docker for a helper container that shares only that container's volumes (`--volumes-from`), has no network, a read-only root file system, `no-new-privileges`, 256 MiB of memory, 64 processes, and only the capabilities `CHOWN`, `DAC_OVERRIDE`, and `FOWNER`. The helper runs the agent's own binary (`loreva-agent files-helper`) from a local image `loreva-agent-files:<digest>` imported from that binary, so nothing is downloaded. Inside the helper every access goes through a directory handle per mount (Go `os.Root`), so neither `..` nor a symbolic link leads out of a mount, even one pointing at `/etc`. The helper works whether the container runs or is stopped, stops after 2 minutes without requests, and Docker removes it. Helpers carry the label `dev.loreva.role=files-helper`; the agent removes leftovers when it starts.

| Request | Answer | Use |
| --- | --- | --- |
| `fs.list` `path`, `after` | `fs.list.result` | One page of up to 500 entries sorted by name; `more` means the next page starts `after` the last name. `/` and other folders above the mounts list only the folders that lead to mounts (`virtual`) |
| `fs.stat` `path` | `fs.stat.result` | One entry, without following a final symbolic link |
| `fs.mkdir` `path` | `fs.result` | New folder |
| `fs.rename` `path`, `to` | `fs.result` | Rename or move within one volume; an existing `to` is refused with `already_exists`, a move to another volume with `cross_device` |
| `fs.chmod` `path`, `mode` | `fs.result` | Permission bits 0 to 0777 (511) of a file or folder; symbolic links are refused |
| `fs.delete` `paths` | `fs.progress`, `fs.result` | Remove files and folders with their content |
| `fs.copy` `paths`, `to` | `fs.progress`, `fs.result` | Copy into the folder `to`, also into another volume (paste). A taken name gets ` (1)`, ` (2)`, … before the extension; `entries` are the copies |
| `fs.archive` `paths`, `to`, `format` | `fs.progress`, `fs.result` | Pack into a new `zip` or `tar.gz` file `to`, to download a large folder as one file |
| `fs.extract` `path`, `to` | `fs.progress`, `fs.result` | Unpack a zip, tar, or tar.gz archive into the folder `to` |
| `fs.read.open` `path`, `offset`, `stream_id` | `fs.read.opened`, then data | Download a file from `offset`, or a folder as an uncompressed tar stream (`archive` true) |
| `fs.write.open` `path`, `size`, `sha256`, `stream_id` | `fs.write.ready`, then `fs.write.result` | Upload or save a file |

`paths` of one request number 1 to 1000; for `fs.copy` and `fs.archive` they must be in one folder. Every entry has `name`, `type` (`file`, `directory`, `symlink`, `other`), `size`, `mode` (permission bits as a number, 0644 is 420), `uid`, `gid`, `modified_at`, and, where they apply, `link_target`, `version`, `mount` (the root of a volume), `virtual`, and `read_only` (the volume is mounted read-only). Mount roots, and folders that contain another mount, cannot be renamed, deleted, or replaced (`mount_root`), and read-only mounts refuse every change (`read_only`). `fs.rename` and `fs.archive` never replace an existing object, even one created while they ran (`already_exists`).

**Long operations.** `fs.delete`, `fs.copy`, `fs.archive`, and `fs.extract` report `fs.progress` (`items` and `bytes` done) up to four times a second and end with `fs.result` carrying the totals and `skipped`: objects the format cannot hold or that were left alone. `fs.cancel` with the operation's `request_id` stops it; it then ends with `error` `cancelled`. At most 4 run at once per session. An archive is written to a temporary file next to `to` and renamed into place when complete; a zip leaves out symbolic links and special files, a tar.gz keeps symbolic links. Extraction creates only folders and regular files, never overwrites an existing file (it counts it in `skipped`), ignores names that are absolute or climb out with `..`, drops set-user-ID and set-group-ID bits, refuses a symbolic link where it needs a folder (`not_a_directory`), and stops at 100000 entries or 64 GiB (`too_large`). Extraction, copies, archives, and uploads also stop with `no_space` before the volume has less than 5 % of its size (at most 1 GiB) free, so the disk the node and its other containers share does not fill. New files and folders get the owner of the folder they are created in, and copies keep the owner of their source, so a server running as an unprivileged user can still change them.

**Download.** The content arrives as binary frames on channel 3 of `stream_id`, with the same layout, 2 MiB window, `stream.credit`, and `stream.close` as a log stream. A file download sends exactly the `size` of `fs.read.opened`'s entry minus `offset`; a folder's tar stream has no announced size and cannot be resumed. To resume an interrupted download, open it again with `offset` set to the bytes already received and check that `version` did not change.

**Upload and editing.** `fs.write.open` announces `size` and the lowercase hex SHA-256 of the whole file. `expected_version` makes the write fail with `version_conflict` unless the file still has that `version` (an opaque string that changes with the content, the modification and change times, and the inode); this is how an editor saves without overwriting a change made meanwhile (open the file, keep its `version`, save with it). `absent` requires that no file exists yet. `mode` (1 to 0777) applies to a new file; a replaced file keeps its mode and owner. After `fs.write.ready` the device sends the content from `offset` in binary frames on channel 3 of `stream_id`, 1 to 32768 bytes each; the device may have up to 2 MiB sent and not yet credited, and the node returns `stream.credit` as it stores data. The node writes into a partial file next to the target, checks the SHA-256, and renames it over the target, so the old file stays intact until the new one is complete; a mismatch fails with `checksum_mismatch`. If the connection breaks, the partial file stays, and the same upload (same path, size, and SHA-256) resumes at the `offset` `fs.write.ready` reports. Partial files older than 7 days are removed when another upload goes to the same folder. A device cancels an upload with `stream.close` `cancelled`; no data for 30 seconds fails it with `upload_timeout`.

Errors carry the request's `request_id` and one of these codes, in addition to those of logs and consoles: `no_volumes`, `files_unavailable`, `invalid_request`, `invalid_path`, `outside_mounts`, `mount_root`, `not_found`, `already_exists`, `not_a_directory`, `is_a_directory`, `not_regular_file`, `not_empty`, `permission_denied`, `read_only`, `cross_device`, `version_conflict`, `checksum_mismatch`, `too_large`, `no_space`, `unsupported_format`, `upload_timeout`, `invalid_credit`, `invalid_frame`, `cancelled`, `failed`. A failed download ends with `stream.close` `failed` and one of these codes.

## Node network report

The node sends `node.specifications.report` (hardware, operating system, platform) once per session. Network and security settings change while the node runs, so they travel separately in `node.network.report`: once per session after the specifications, and again whenever a device or the portal sends `node.network.refresh` with a `request_id`. The refreshed report is an ordinary `node.network.report` with its own `request_id` and is acknowledged like the first one. Metrics keep flowing while it is collected; refreshes asked for while a report is in flight are merged into one that runs afterwards.

The report carries everything an administrator usually checks over SSH, in full. Masking sensitive values is the client's job.

- `interfaces`: addresses, MAC, MTU, flags, `oper_state`, `speed_bps`, and `duplex`.
- `routes`, `listening_ports` (with `pid` and `process_name` of the owner), and `firewall`.
- `dns`: `nameservers` and `search_domains` from `/etc/resolv.conf`, `resolver` (`systemd-resolved` when the stub 127.0.0.53 is used), and its `upstream` servers.
- `public_addresses`: one entry per address with `family`, `address`, `source`, and `behind_nat` (the address is not on any interface of the node). Sources are tried in this order and the first that answers wins per family:
  1. `configured`: the `LOREVA_PUBLIC_IP` environment variable, a comma-separated list. It replaces every lookup.
  2. `interface`: a public address on one of the node's interfaces. Such a family is not looked up outside.
  3. `cloud_metadata`: the metadata service of AWS (IMDSv2), Google Cloud, Azure, Hetzner, or DigitalOcean, asked only when the machine's DMI vendor names that provider.
  4. `external`: the "what is my IP" services the Datadog Agent uses: icanhazip.com, ipinfo.io, checkip.amazonaws.com, api.ipify.org (api64.ipify.org for IPv6), and whatismyip.akamai.com. The node connects directly over the requested family, without a proxy or redirects, and accepts an address only when at least two operators return it. One answer is reported as `public_addresses.<family>` `unconfirmed`, disagreement as `inconsistent`, no answer as `not_available`.

  `LOREVA_PUBLIC_IP_LOOKUP=off` disables metadata and outside lookups. Results of lookups are cached for 30 minutes.
- `security.ssh`: whether sshd is `running`, its `configured_ports` and `listening_ports`, and `permit_root_login`, `password_authentication`, and `pubkey_authentication` from `sshd_config` (first value wins, `Include` is followed).
- `security.intrusion_prevention`: fail2ban (with its enabled jails) and CrowdSec, each with `status` and `details`.
- `security.mandatory_access_control`: AppArmor and SELinux.

When the agent runs in a container without the host's network namespace, interfaces, routes, sockets, and counters are still read from the host's `/proc/1/net`, but firewall rules belong to the namespace: the report lists the firewall providers it found without rules and adds the issue `firewall.rules` `other_namespace`. Running the agent with the host network makes the rules visible.

## Metric units

- Node CPU (`cpu.total.usage_percent`, `cpu.logical[].usage_percent`) is a share of the whole machine or of one logical CPU: 0 to 100.
- Container CPU (`cpu.usage_percent`) follows `docker stats`: 100 is one fully busy logical CPU, so a container can report up to `online_cpus` × 100. For example, 161 on a 4-CPU node is about 1.6 CPUs, or 40 % of the machine. `online_cpus` is the number of logical CPUs the container sees. `limit_cores` is present only when a CPU quota or cpuset caps the container below `online_cpus`; then `usage_percent / limit_cores` is the share of its limit in percent.
- Memory and swap report `total_bytes` and `swap_total_bytes` next to the used amounts. File systems report `device`, `filesystem_type`, and `total_bytes`; `used_percent` follows `df`: used against used plus available to unprivileged users.
- `*_total` fields of network interfaces and storage devices are the kernel's counters since boot, so traffic over a period is the difference of two samples. In a rollup the `max` of such a series is its value at the end of the window.
- `tcp` covers IPv4 and IPv6 of the host's network namespace: `established` and `time_wait` connections, `orphaned` sockets, sockets `in_use`, and per-second rates of opened (`active_opens`, `passive_opens`), failed, and reset connections and retransmitted segments. It comes from `/proc/net/snmp` and `/proc/net/sockstat`, which stay cheap on servers with many connections, and is left out until two samples exist.
- A process item has no command line, which can be long and is sent every second. `node.process.inspect` with the item's `pid` and `started_at` returns `node.process.inspect.result` with `command_line` as an argument list (cut at 32 KiB, then `command_line_truncated` is set) and the process's identity. A process that has exited or whose PID was reused is answered with `error` `not_found`. Command lines are returned in full, including any passwords in them; masking them is the client's job.
- A component that could not be measured is listed in `collection_issues` instead of being silently left out. For file systems the agent reports `storage.filesystems` with `not_available` when it can see none (for example in a container without the host's mount table) and `partial` when some could not be read. A failed CPU limit lookup is reported as `containers.docker.limits` `partial`.

## Metrics store

The agent writes every metrics sample into a store on disk and serves every reader from it: the portal and each paired device are readers with their own cursor, the last sequence they acknowledged. A reader that was offline receives everything it missed on its next connection; data leaves the store only by age, never because a reader read it. A newly paired device starts at the oldest stored data. Revoking a device deletes its cursor.

| Age | Kept as |
| --- | --- |
| Up to 1 hour | Every sample (process lists only for the last 5 minutes) |
| 1 hour to 1 day | One rollup per minute. Neighbouring minutes that differ only by noise (under 2 percentage points for `*_percent` series, under 2 % otherwise) are merged. A minute with a spike (a `*_percent` series moving 10 points or more, or another series moving by half its average) keeps all its samples |
| 1 day to 7 days | One rollup per hour |
| Older | Removed; the store also drops its oldest data above 200 MB |

A rollup (`metricRollup`) covers `first_sequence` to `last_sequence` and holds, for every numeric series, `min`, `avg`, `max`, and `max_at` (when the peak happened). A series is named by the path of a numeric field of the sample; array elements are named by their identifier field, for example `cpu.total.usage_percent` or `network.network:2.rx_bytes_per_second`.

Delivery reads the store in sequence order. Full samples go out as `metrics.report`, up to 60 samples per frame; compacted windows go out as `metrics.rollup`, up to 60 rollups per frame. Each batch is a `node` frame followed by a `container` frame with the same items, and the reader's cursor moves when the second frame is acknowledged. `stream_id` identifies the store and stays the same across restarts, and `sequence` keeps growing within it, so a reader can drop duplicates by sequence. A sample's node and container frames carry the same `sequence`.

The store lives in `metrics/` in the agent's state directory as DEFLATE-compressed JSON records, mode 0600.

## Rules outside JSON Schema

- Frames carry JSON in text frames. The only binary frames are stream data: the node's log and download data described in [Container logs and consoles](#container-logs-and-consoles), and upload data on channel 3 described in [Files in container volumes](#files-in-container-volumes). JSON is strict: unknown fields, duplicate keys, trailing data, and multiple values are rejected.
- The normal inbound frame limit is 64 KiB. Node reports are bounded to 512 KiB, and their collected snapshot is bounded to 480 KiB.
- Challenge expiry, JWS signatures and claims, certificate validation, source expiry and URL canonicalization, monotonic source generations, request correlation, enrollment idempotency, workload ownership, plan approvals, and retry state are semantic checks performed by the implementations.
- A workload command is bound to the current `connect.challenge` nonce, exact portal and node identities, a maximum 60-second lifetime, and at most 30 seconds of positive clock skew.
- OCI images must be pinned by `sha256`. Compose/Egg mutable runtime image references, installer scripts, host binds, Docker socket access, privileged containers, host namespaces, devices, and local builds become explicit findings requiring approval. Egg installer images must always be pinned. The agent state directory and host filesystem root cannot be bind-mounted.
- Compose host-side files, build contexts, `env_file`, `label_file`, configs, secrets, and credential files must remain inside the signed artifact. `include`, `extends`, additional build contexts, SSH forwarding, and external build caches are rejected in schema v1 because they bypass that boundary. External Docker configs, secrets, links, lifecycle hooks, and credential specifications become explicit findings where supported.
- A repeated workload operation `request_id` replays its persisted result only when its semantic command fields match: type, schema, request, portal, node, workload, and payload. Session nonce and timestamps may change when the portal re-signs an otherwise identical command after reconnect. A crash after mutation begins returns `operation_outcome_unknown` instead of executing the request twice.
- A report retry reuses the exact payload and `request_id`. An accepted/rejected response echoes only that `request_id`; metrics do not use a separate `batch_id` or processing counters.
- Enrollment idempotency is defined by the `jti` inside `pq_pop`: identical key material resumes the same node, conflicting material is rejected, and a different `jti` creates another node even when the reusable enrollment token is the same.
- Breaking field changes require a new protocol version. Adding an optional field to an existing v1 object is breaking because v1 decoders reject unknown fields.

The Go contract test compiles this schema, validates canonical messages produced from every wire DTO, and compares each object definition with its Go JSON fields. It runs through the existing `go test ./...` release gate.
