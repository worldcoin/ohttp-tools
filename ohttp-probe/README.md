# ohttp-probe

CLI tool to test [Oblivious HTTP (RFC 9458)](https://www.rfc-editor.org/rfc/rfc9458.html) gateways.
It fetches the OHTTP key configuration, encrypts a test payload using HPKE, sends it to the gateway,
and verifies the decrypted response matches.

## Requirements

- Go 1.26+
- [Task](https://taskfile.dev) v3+

## Quick start

```sh
cd ohttp-probe

task build              # build the binary
task test-backends      # probe every staging backend /health via relay
task test-backends-prod # probe every production backend /health via relay
```

## Modes

The probe has three modes, selected by `-mode`:

### `-mode echo` (default)

POSTs an HPKE-encrypted payload directly to the gateway ALB's `/gateway-echo`
endpoint and verifies the decrypted response equals the original payload.
Pure crypto round-trip — no backend involved, no relay:

```sh
./ohttp-probe -mode echo https://ohttp-stage.us.id-infra.worldcoin.dev
./ohttp-probe -mode echo -v -p "test-123" -t 30s \
  https://ohttp-stage.us.id-infra.worldcoin.dev \
  https://ohttp-stage.eu.id-infra.worldcoin.dev
```

Echo mode talks to the ALB directly, so it only passes when infra has
temporarily set `open_to_all = true; mtls_enabled = false` on the ALB for
debugging.

### `-mode relay`

Sends a BHTTP-encoded inner request through the Cloudflare Privacy Gateway
relay. The inner request targets a real backend (specified via `-target`):

```sh
./ohttp-probe -mode relay -v \
  -keys https://ohttp-keys.us.id-infra.worldcoin.dev/ohttp-keys \
  -target gateway.us.id-infra.worldcoin.dev \
  -target-path /health \
  https://staging.privacy-relay.cloudflare.com/us-world-id-stage
```

This exercises the full client → relay → gateway → backend path and is the
closest thing to what real wallets do.

### `-mode direct`

Same as relay mode, but the encrypted request is POSTed straight to the
gateway ALB's `/gateway` endpoint, bypassing the Cloudflare relay. Requires
ALB mTLS temporarily disabled (same caveat as echo mode):

```sh
./ohttp-probe -mode direct -v \
  -keys https://ohttp-keys.us.id-infra.worldcoin.dev/ohttp-keys \
  -target indexer.us.id-infra.worldcoin.dev \
  -target-path /health \
  https://ohttp-stage.us.id-infra.worldcoin.dev
```

Useful for isolating whether a failure lives in the Cloudflare relay leg or
the gateway-and-below part of the stack.

## Load mode (`-load`)

Drives `relay` or `direct` mode at `-qps` requests per second for `-duration`
using [vegeta](https://github.com/tsenart/vegeta)'s open-model attacker —
workers grow organically with offered load, so tail latency isn't masked by a
fixed worker pool. Keys are fetched once up-front. Prints a plain-text summary
with p50/p95/p99 latency and per-category error counts. Abort with `Ctrl-C`.

Echo mode is rejected under `-load` — it skips the backend and relay, so load
numbers would reflect only the gateway's HPKE encrypt/decrypt cost, not the
path real clients exercise.

```sh
./ohttp-probe -mode relay -load \
  -qps 20 -duration 30s \
  -keys https://ohttp-keys.us.id-infra.worldcoin.dev/ohttp-keys \
  -target indexer.us.id-infra.worldcoin.dev \
  -target-path /health \
  https://staging.privacy-relay.cloudflare.com/us-world-id-stage
```

Error categories in the summary:

- `transport` — TCP/TLS errors, client timeouts, outer non-200 from the relay or ALB
- `decrypt` — content-type mismatches, OHTTP/BHTTP unmarshal, HPKE decapsulate failures
- `inner HTTP` — successful OHTTP round-trip where the decrypted inner response is non-2xx

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-mode` | `echo` | One of `echo`, `relay`, `direct` |
| `-p` | `hello from ohttp-probe` | Payload to send via `/gateway-echo` (echo mode only) |
| `-t` | `10s` | HTTP timeout |
| `-health` | `false` | Only check `/health` on the base URL (skip OHTTP crypto) |
| `-keys` | | URL to fetch OHTTP keys from (required for `-mode relay` and `-mode direct`) |
| `-target` | | Target origin for inner BHTTP request (required for `-mode relay` and `-mode direct`) |
| `-target-path` | `/health` | Path to request on the target origin (relay/direct modes) |
| `-v` | `false` | Verbose output |
| `-load` | `false` | Run as load test (requires `-mode relay` or `-mode direct`) |
| `-duration` | `30s` | Load test duration (load mode) |
| `-qps` | | Target requests per second (load mode; required, open-model attacker) |

## Task targets

| Target | Description |
|--------|-------------|
| `task test-backends` | Probe every staging backend (`indexer` all regions + `gateway` US) `/health` via Cloudflare Privacy Gateway |
| `task test-backends-prod` | Probe every production backend `/health` via Cloudflare Privacy Gateway |
| `task test-backends-direct` | Probe every staging backend `/health` directly on the gateway ALB (requires ALB mTLS disabled) |
| `task test-backends-direct-prod` | Probe every production backend `/health` directly on the gateway ALB (requires ALB mTLS disabled) |
| `task test-echo` | Probe every staging gateway `/gateway-echo` directly (requires ALB mTLS disabled) |
| `task test-echo-prod` | Probe every production gateway `/gateway-echo` directly (requires ALB mTLS disabled) |
| `task load` | Load-test a staging region via the Cloudflare Privacy Gateway relay |
| `task load-prod` | Load-test a production region via the Cloudflare Privacy Gateway relay (coordinate with infra on CF quota) |

### Load task overrides

Both `load` targets accept CLI variables to tune the run. Defaults:
`REGION=us`, `DURATION=30s`, `QPS=10`,
`TARGET_HOST=indexer.<REGION>.id-infra.<env>`.

```sh
# Default: stage us indexer, 30s at 10 rps
task load

# EU stage, 60s at 50 rps
task load REGION=eu DURATION=60s QPS=50

# Prod us gateway instead of indexer
task load-prod TARGET_HOST=gateway.us.id-infra.world.org
```

## How it works

### Echo mode

1. **Fetch keys** — `GET /ohttp-keys` returns the gateway's HPKE public key config
2. **Encrypt** — the payload is encapsulated using OHTTP (HPKE)
3. **Send** — `POST /gateway-echo` with `Content-Type: message/ohttp-req`
4. **Decrypt** — the encrypted response is decapsulated and compared to the original payload

### Relay mode

1. **Fetch keys** — `GET <keys-url>` returns the gateway's HPKE public key config
2. **Build inner request** — a BHTTP-encoded `GET <target-path>` with `Host: <target>`
3. **Encrypt** — the BHTTP request is encapsulated using OHTTP
4. **Send** — `POST <relay-url>` with `Content-Type: message/ohttp-req`; Cloudflare forwards the blob to the gateway, which decrypts, forwards the inner HTTP request to the target, and re-encrypts the response
5. **Decrypt** — the OHTTP response is decapsulated, the inner BHTTP response is parsed, and the HTTP status is verified

### Direct-BHTTP mode

Identical to relay mode except step 4 POSTs to `<base>/gateway` on the gateway ALB instead of the Cloudflare relay URL.

## Exit codes

- `0` — all probes passed
- `1` — one or more probes failed
