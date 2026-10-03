# Loreva Agent protocols

This document describes every interface of the agent:

1. [Direct access](#1-direct-access): how a client such as Loreva App connects to a node with no portal or cloud service. This covers node setup, the connection key (invite), WireGuard settings, pairing, and the credentials a device keeps. The HTTP API inside the tunnel is specified in [api/openapi.yaml](api/openapi.yaml).
2. [Control socket](#2-control-socket): the local root-only interface used by `loreva-agent invite` and `loreva-agent devices`.
3. [Portal protocol](#3-portal-protocol): the optional outbound WSS connection to a Loreva portal.

Byte-level details are normative; the Go reference implementation is in `internal/pairing`, `internal/direct`, and `internal/client`.

## 1. Direct access

### 1.1 Overview

```text
loreva-app (device)                                    node (loreva-agent run)
        |                                                         |
        |  operator: sudo loreva-agent invite  -> prints loreva1:...
        |  user pastes the connection key into the app            |
        |== WireGuard handshake as the temporary invite peer =====>|  UDP, node's listen port
        |-- POST /v1/pairing (device key, ML-KEM key, name) ------>|  invite consumed
        |<- pairing_id, nonce, ML-KEM ciphertext, device address --|
        |  app shows code ABCD-EFGH        CLI shows code ABCD-EFGH, asks y/N
        |-- GET /v1/pairing/{id} (long poll) --------------------->|  operator answers y
        |<- approved, device_id -----------------------------------|  device peer added
        |== WireGuard handshake with the device's own key and PSK =>|
        |-- GET /v1/node ... ------------------------------------->|
```

Properties:

- The node opens one UDP port and no TCP port on the host. The HTTP API listens only on the node's address inside its userspace WireGuard network stack.
- The agent never creates a network interface, route, or firewall rule, and never touches sshd or DNS.
- The node authenticates to the device with its WireGuard static key, which the device learns from the connection key.
- Each device has its own WireGuard key, its own PSK, and one tunnel address. The address identifies the device to the API.
- The device PSK comes from an ML-KEM-768 exchange. Recorded traffic therefore stays confidential against a future quantum attacker who breaks X25519. The invite PSK protects only the pairing exchange itself.
- A connection key is single use and expires (15 minutes by default, 1 hour at most). It exists only in the memory of the agent and of the `invite` command, and dies when that command exits.

### 1.2 Node setup

`loreva-agent init [--port N] [--endpoint IP[:PORT]]...` creates `node.json` in the state directory (mode 0600):

| Field | Meaning |
| --- | --- |
| `node_id` | Random UUID v4. |
| `wireguard_private_key` | Curve25519 private key, standard Base64. |
| `listen_port` | UDP port. The default is a random port between 20000 and 32000 that is free when `init` runs. |
| `tunnel_prefix` | Random unique local IPv6 `/64` (RFC 4193: `fd` followed by a 40-bit random global ID, subnet 0). |
| `endpoints` | Optional public addresses to advertise, as `IP:port`. |

The node's tunnel address is the first address of the prefix (`<prefix>::1`). Every invite peer and device gets a random 64-bit interface ID in the same prefix.

`init` never replaces an existing `node.json`. Paired devices are stored in `devices.json` next to it, including each device's PSK, so the state directory must stay private.

If inbound UDP to the listen port is filtered, the operator must allow it. The agent does not change the firewall.

### 1.3 Connection key (invite)

The connection key is the string `loreva1:` followed by the unpadded Base64URL (RFC 4648 §5) encoding of a UTF-8 JSON object:

| Field | Type | Meaning |
| --- | --- | --- |
| `v` | integer | Format version, `1`. |
| `invite_id` | UUID | Identifies this invite in the transcript. |
| `node_id` | UUID | The node. |
| `node_public_key` | Base64 key | The node's WireGuard public key. This value authenticates the node. |
| `node_address` | IPv6 | The node's tunnel address. The API is at `http://[node_address]:80`. |
| `endpoints` | array of `IP:port` | 1 to 16 outer UDP endpoints, tried in order. IP literals only (no host names) and no zone. |
| `invite_private_key` | Base64 key | Private key of the temporary invite peer. |
| `invite_preshared_key` | Base64 key | PSK of the temporary invite peer. |
| `invite_address` | IPv6 | Tunnel address of the temporary invite peer. |
| `expires_at` | RFC 3339 | Expiry time, UTC. The node enforces it. |

Base64 keys are the standard encoding (with padding) of 32 bytes, as `wg` uses. A parser must reject:

- a key longer than 4096 bytes;
- a missing prefix or non-canonical Base64URL;
- unknown fields, or duplicate fields including fields that differ only by letter case;
- a version other than 1;
- invalid UUIDs;
- an all-zero key;
- tunnel addresses that are not distinct IPv6 addresses;
- an empty or oversized endpoint list;
- a zero expiry.

The connection key is a secret: whoever presents it first can start pairing. It is not signed, because it travels together with the key it would be signed with. Its integrity rests on the channel the operator uses to copy it, and on the code comparison in §1.5.

### 1.4 WireGuard settings

A client runs WireGuard with:

- the node peer's public key set to `node_public_key`, its endpoint set to one of `endpoints`, and allowed IPs set to `node_address/128`;
- the local interface address set to `invite_address` (during pairing) or the device's own address (afterwards), MTU 1280;
- the preshared key set to `invite_preshared_key` (during pairing) or the device PSK (afterwards);
- a persistent keepalive of 25 seconds, recommended for clients behind NAT.

The node configures each peer with exactly one allowed IP, its `/128`, and always with a non-zero PSK.

To choose an endpoint, the client opens a TCP connection to `[node_address]:80` through each endpoint in turn, with a 5-second timeout. The first success proves the WireGuard handshake with the node's key completed.

### 1.5 Pairing

Pairing has three steps.

**Step 1: the device generates new keys and commits to them.** As the invite peer, the device generates a new Curve25519 key pair and a new ML-KEM-768 key pair, then sends `POST /v1/pairing`:

```json
{
  "device_name": "Rick's laptop",
  "wireguard_public_key": "<Base64 32 bytes>",
  "mlkem_encapsulation_key": "<Base64 1184 bytes>"
}
```

**Step 2: the node answers.** The node:

1. validates the name (1 to 64 printable characters) and the keys. A request that fails validation does not use up the invite;
2. marks the invite as used. A later call returns `409 invite_used`;
3. allocates `device_address`, generates a 32-byte `node_nonce`, and encapsulates against the device's key: `(ss, ct) = ML-KEM-768.Encaps(ek)` (FIPS 203);
4. returns:

```json
{
  "pairing_id": "<UUID>",
  "node_nonce": "<Base64 32 bytes>",
  "mlkem_ciphertext": "<Base64 1088 bytes>",
  "device_address": "<IPv6>"
}
```

The device committed to its keys and name before it learned `node_nonce`. An attacker therefore cannot search for keys whose code collides with the honest one.

**Step 3: both sides compute the transcript, the code, and the PSK.**

```text
field(x) = uint32_be(len(x)) || x

th = SHA-256(
  field("loreva.pairing.transcript.v1") ||
  field(invite_id as ASCII)             ||
  field(node_id as ASCII)               ||
  field(node WireGuard public key, 32 bytes)   ||
  field(device WireGuard public key, 32 bytes) ||
  field(device_name as UTF-8)           ||
  field(device_address, 16 bytes)       ||
  field(ML-KEM encapsulation key, 1184 bytes)  ||
  field(ML-KEM ciphertext, 1088 bytes)  ||
  field(node_nonce, 32 bytes)
)

code   = Base32(SHA-256("loreva.pairing.sas.v1" || th))[0:8]   (RFC 4648 alphabet)
shown  = code[0:4] + "-" + code[4:8]                           (40 bits)

device_psk = HKDF-SHA-256(
  IKM  = ss || th,
  salt = invite_preshared_key (32 bytes),
  info = "loreva.pairing.psk.v1",
  L    = 32)
```

The device shows the code. The `invite` command shows the node's code, together with the device name and key, and asks the operator to approve only when both codes match. A mismatch means someone else used the connection key, or the exchange was tampered with.

The device long-polls `GET /v1/pairing/{pairing_id}`. The status is one of:

- `pending`: call again;
- `approved`: the response includes `device_id`;
- `rejected`: the operator answered no;
- `expired`: the invite expired, or the `invite` command exited before the operator decided.

After any final status, including `expired`, the invite peer stays configured for about 30 seconds so the device can read it.

On approval the node saves the device and adds its WireGuard peer (device key, `device_psk`, `device_address/128`). The device then reconnects with its own key, `device_psk`, and `device_address`. The invite peer stays configured for about 30 seconds after the decision, so the device can read the final status, and is then removed.

The invite peer can call only the two pairing operations; every other endpoint returns `403`.

`loreva-agent invite --no-confirm` approves the first device without a code comparison. It is meant for automation in which the connection key travels over an already trusted channel. It is weaker than the default.

### 1.6 Device credentials

After pairing, a device must keep the following, secret and readable only by its owner:

- `node_id`, `node_public_key`, `node_address`, and the endpoints;
- its `device_id`, private key, `device_psk`, and `device_address`.

`loreva-agent device pair` stores these as a JSON file with mode 0600, in the same form as `client.Credentials`.

A device never needs the invite again.

### 1.7 Revocation

A paired device can revoke any device, itself included, with `DELETE /v1/devices/{id}`. The operator can do the same on the node with `sudo loreva-agent devices remove <id>`. In both cases the device loses API access at once and its WireGuard peer is removed.

To recover access without any paired device, the operator runs `sudo loreva-agent invite` on the node again.

## 2. Control socket

The running agent listens on `control.sock` in its state directory. The socket has mode 0600, and the agent accepts only peers whose kernel-reported UID (`SO_PEERCRED`) is 0 or the agent's own UID. The socket is supported on Linux only.

Messages are JSON objects separated by newlines, at most 64 KiB each, and decoded strictly. Every message has a `type`:

| Direction | `type` | Fields |
| --- | --- | --- |
| CLI → agent | `invite.create` | `ttl_seconds` (60–3600, default 900), `endpoints` (optional IP or IP:port list to put first), `no_confirm` |
| agent → CLI | `invite.created` | `invite`, `expires_at` |
| agent → CLI | `pairing.requested` | `pairing_id`, `device_name`, `fingerprint` (device WireGuard public key), `sas` |
| CLI → agent | `pairing.decision` | `pairing_id`, `approve` |
| agent → CLI | `pairing.completed` | `pairing_id`, `device_id`, `device_name` |
| agent → CLI | `pairing.rejected` | `pairing_id` |
| agent → CLI | `invite.expired` | none |
| CLI → agent | `devices.list` | none |
| agent → CLI | `devices` | `devices` (`id`, `name`, `wireguard_public_key`, `tunnel_address`, `paired_at`) |
| CLI → agent | `device.remove` | `device_id` |
| agent → CLI | `device.removed` | `device_id` |
| agent → CLI | `error` | `error` |

A connection holds at most one invite. Closing the connection cancels the invite. A pending pairing ends as `expired`, and the invite peer then stays for the same 30-second grace period that follows a decision.

## 3. Portal protocol

Portal mode is optional. A node can run direct access, the portal session, or both; `loreva-agent run` starts each mode whose state file exists (`node.json`, `identity.json`).

All portal traffic is outbound WSS from the agent:

- TLS 1.3 only, with the hybrid post-quantum key exchange `X25519MLKEM768` as the only group;
- a portal CA can be pinned in the bootstrap configuration.

Every message is a JSON text frame with a `type` field and is decoded strictly. The types are defined in `internal/protocol`.

**Enrollment.** The agent connects to `/agent/v1/enroll` with subprotocol `loreva.enrollment.v1` and `Authorization: Bearer <enrollment token>`. The exchange is:

1. the portal sends `enrollment.challenge`;
2. the agent sends `enrollment.request` with:
   - an ECDSA P-256 CSR;
   - an ML-DSA-65 proof of possession (compact JWS), bound to the portal ID, the challenge nonce, and the expiry;
3. the portal answers `enrollment.accepted` or `enrollment.rejected`. The accepted message carries:
   - `node_id`;
   - the certificate chain;
   - the portal's ML-DSA root as a JWK;
   - an ML-DSA credential;
   - `renew_after`;
   - the gateway pool (`sources`).

The agent stores the result in `identity.json`.

**Session.** The agent connects to `/agent/v1/connect` with subprotocol `loreva.connect.v1` and presents its client certificate. The exchange is:

1. the portal sends `connect.challenge` as a JWS signed by its ML-DSA root;
2. the agent sends `connect.proof`;
3. the portal answers `connect.accepted` or `connect.rejected`.

During the session:

- the agent sends `node.specifications.report` and `node.network.report`, which the portal answers with `*.accepted` or `*.rejected`;
- the portal can send `sources.update` with a new gateway pool and `drain` to move the agent to another gateway;
- the agent rotates its identity with `renew.request`, answered by `renew.accepted` or `renew.rejected`.
