# Loreva agent WSS protocol v1

`protocol.schema.json` is the normative, repository-local contract for every JSON text frame exchanged on:

| Endpoint | WebSocket subprotocol | Authentication |
| --- | --- | --- |
| `/agent/v1/enroll` | `loreva.enrollment.v1` | Enrollment bearer token during Upgrade |
| `/agent/v1/connect` | `loreva.connect.v1` | TLS 1.3 mTLS followed by ML-DSA proof |

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

After `connect.accepted`, the agent can send `renew.request`, `node.specifications.report`, `node.network.report`, and `metrics.report`. A metrics frame contains `metric.type`: `node`, `container`, or a versioned `plugin:<name>` adapter namespace. The portal can send the correlated accepted/rejected responses, `sources.update`, `drain`, or a signed `portal.command`.

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

## Rules outside JSON Schema

- Only text frames are accepted. JSON is strict: unknown fields, duplicate keys, trailing data, and multiple values are rejected.
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
