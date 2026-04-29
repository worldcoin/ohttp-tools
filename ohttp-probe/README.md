# ohttp-probe

CLI tool to test [Oblivious HTTP (RFC 9458)](https://www.rfc-editor.org/rfc/rfc9458.html) gateways.
It fetches the OHTTP key configuration, encapsulates a request using HPKE, sends it to the gateway
(directly or via a relay), and verifies the decrypted response.

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

## Commands

The probe has three subcommands. Each has its own `-h` for command-specific
flags. There is no `-mode` flag — relay vs direct-to-gateway is chosen by
which URL you pass to `-relay-url`.

### `echo`

POSTs an HPKE-encrypted payload to each `-gateway-url`'s `/gateway-echo`
endpoint and verifies the decrypted response equals the payload. Pure crypto
round-trip — no backend, no relay. Requires ALB mTLS temporarily disabled
when probing remote production gateways.

```sh
./ohttp-probe echo -v \
  -gateway-url https://ohttp-stage.us.id-infra.worldcoin.dev \
  -gateway-url https://ohttp-stage.eu.id-infra.worldcoin.dev
```

### `probe`

Sends one BHTTP-encoded inner GET per `-target-url` through `-relay-url`.
Targets are probed concurrently; exit code is non-zero if any fail. The
relay can be a Cloudflare Privacy Gateway URL, a gateway's `/gateway`
endpoint (direct mode), or any RFC 9458 server.

```sh
# Through Cloudflare Privacy Gateway
./ohttp-probe probe -v \
  -relay-url https://staging.privacy-relay.cloudflare.com/us-world-id-stage \
  -keys-url https://ohttp-keys.us.id-infra.worldcoin.dev/ohttp-keys \
  -target-url https://gateway.us.id-infra.worldcoin.dev/health \
  -target-url https://indexer.us.id-infra.worldcoin.dev/health

# Direct to the gateway ALB (bypasses Cloudflare; requires ALB mTLS disabled)
./ohttp-probe probe -v \
  -relay-url https://ohttp-stage.us.id-infra.worldcoin.dev/gateway \
  -keys-url https://ohttp-keys.us.id-infra.worldcoin.dev/ohttp-keys \
  -target-url https://indexer.us.id-infra.worldcoin.dev/health
```

Useful for isolating whether a failure lives in the Cloudflare relay leg or
the gateway-and-below part of the stack: probe through the relay, then
direct to the gateway, and compare.

### `load`

Drives a single `-target-url` through `-relay-url` at `-qps` requests per
second for `-duration`, using
[vegeta](https://github.com/tsenart/vegeta)'s open-model attacker — workers
grow with offered load, so tail latency isn't masked by a fixed worker
pool. Keys are fetched once up-front. Prints a plain-text summary with
p50/p95/p99 latency and per-category error counts. Abort with `Ctrl-C`.

```sh
./ohttp-probe load \
  -relay-url https://staging.privacy-relay.cloudflare.com/us-world-id-stage \
  -keys-url https://ohttp-keys.us.id-infra.worldcoin.dev/ohttp-keys \
  -target-url https://indexer.us.id-infra.worldcoin.dev/health \
  -qps 20 -duration 30s
```

Error categories in the summary:

- `transport` — TCP/TLS errors, client timeouts, outer non-200 from the relay or ALB
- `decrypt` — content-type mismatches, OHTTP/BHTTP unmarshal, HPKE decapsulate failures
- `inner HTTP` — successful OHTTP round-trip where the decrypted inner response is non-2xx

## Shared concepts

Three URL flags appear across the subcommands. The relationship between
them is:

```
client → POST <relay-url> → gateway → GET <target-url>
                ↑
       <keys-url> serves the gateway's HPKE key config
```

| Flag | Description |
|---|---|
| `-relay-url` | URL the OHTTP request is POSTed to. Cloudflare relay, gateway `/gateway` endpoint, or any RFC 9458 server. |
| `-keys-url` | URL of the gateway's OHTTP key config (e.g. `https://<gateway>/ohttp-keys`). |
| `-target-url` | Full URL of the inner target the BHTTP request is forwarded to. Repeatable in `probe`; single in `load`. |
| `-gateway-url` | Echo-only: gateway base URL. Probe POSTs to `<gateway-url>/gateway-echo`; keys are read from `<gateway-url>/ohttp-keys`. Repeatable. |

Inner request method is always `GET` — the tool tests OHTTP setup, not
arbitrary endpoint behavior.

## Task targets

| Target | Description |
|---|---|
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

### Echo (`echo`)

1. **Fetch keys** — `GET <gateway-url>/ohttp-keys` returns the gateway's HPKE public key config
2. **Encrypt** — the payload is encapsulated using OHTTP (HPKE)
3. **Send** — `POST <gateway-url>/gateway-echo` with `Content-Type: message/ohttp-req`
4. **Decrypt** — the encrypted response is decapsulated and compared to the original payload

### Probe (`probe`) and load (`load`)

1. **Fetch keys** — `GET <keys-url>` returns the gateway's HPKE public key config
2. **Build inner request** — a BHTTP-encoded `GET` of `-target-url`
3. **Encrypt** — the BHTTP request is encapsulated using OHTTP
4. **Send** — `POST <relay-url>` with `Content-Type: message/ohttp-req`. Cloudflare (or the gateway directly) forwards the blob to the gateway, which decrypts, dispatches the inner HTTP request to the target, and re-encrypts the response.
5. **Decrypt** — the OHTTP response is decapsulated, the inner BHTTP response is parsed, and the inner HTTP status is verified

## Exit codes

- `0` — all probes passed
- `1` — one or more probes failed
- `2` — flag parse error / missing required argument
