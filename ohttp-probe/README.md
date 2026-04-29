# ohttp-probe

CLI tool to test [Oblivious HTTP (RFC 9458)](https://www.rfc-editor.org/rfc/rfc9458.html) gateways.
It fetches the OHTTP key configuration, encapsulates a request using HPKE, sends it to the gateway
(directly or via a relay), and verifies the decrypted response.

## Requirements

- Go 1.26+

## Build

```sh
cd ohttp-probe
go build .
```

## Commands

The probe has three subcommands. Each has its own `-h` for command-specific
flags. There is no `-mode` flag — relay vs direct-to-gateway is chosen by
which URL you pass to `-relay-url`.

### `echo`

POSTs an HPKE-encrypted payload to each `-gateway-url`'s `/gateway-echo`
endpoint and verifies the decrypted response equals the payload. Pure crypto
round-trip — no backend, no relay. The gateway must accept unauthenticated
requests on its OHTTP listener for echo to work (in a Cloudflare-fronted
deployment this typically means temporarily disabling the ALB's mTLS).

```sh
./ohttp-probe echo -v \
  -gateway-url https://gateway.example.com \
  -gateway-url https://gateway.eu.example.com
```

### `probe`

Sends one BHTTP-encoded inner GET per `-target-url` through `-relay-url`.
Targets are probed concurrently; exit code is non-zero if any fail. The
relay can be an [Oblivious Privacy Relay](https://blog.cloudflare.com/announcing-cloudflare-privacy-gateway/)
URL, a gateway's `/gateway` endpoint (direct mode), or any RFC 9458 server.

```sh
# Through an Oblivious Relay
./ohttp-probe probe -v \
  -relay-url https://relay.example.com/some-tenant \
  -keys-url https://gateway.example.com/ohttp-keys \
  -target-url https://api.example.com/health \
  -target-url https://other-api.example.com/health

# Direct to the gateway (no relay leg)
./ohttp-probe probe -v \
  -relay-url https://gateway.example.com/gateway \
  -keys-url https://gateway.example.com/ohttp-keys \
  -target-url https://api.example.com/health
```

Useful for isolating whether a failure lives in the relay leg or the
gateway-and-below part of the stack: probe through the relay, then
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
  -relay-url https://relay.example.com/some-tenant \
  -keys-url https://gateway.example.com/ohttp-keys \
  -target-url https://api.example.com/health \
  -qps 20 -duration 30s
```

Error categories in the summary:

- `transport` — TCP/TLS errors, client timeouts, outer non-200 from the relay or gateway
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
| `-relay-url` | URL the OHTTP request is POSTed to. Privacy relay, gateway `/gateway` endpoint, or any RFC 9458 server. |
| `-keys-url` | URL of the gateway's OHTTP key config (e.g. `https://<gateway>/ohttp-keys`). |
| `-target-url` | Full URL of the inner target the BHTTP request is forwarded to. Repeatable in `probe`; single in `load`. |
| `-gateway-url` | Echo-only: gateway base URL. Probe POSTs to `<gateway-url>/gateway-echo`; keys are read from `<gateway-url>/ohttp-keys`. Repeatable. |

Inner request method is always `GET` — the tool tests OHTTP setup, not
arbitrary endpoint behavior.

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
4. **Send** — `POST <relay-url>` with `Content-Type: message/ohttp-req`. The relay (or the gateway directly) forwards the blob to the gateway, which decrypts, dispatches the inner HTTP request to the target, and re-encrypts the response.
5. **Decrypt** — the OHTTP response is decapsulated, the inner BHTTP response is parsed, and the inner HTTP status is verified

## Exit codes

- `0` — all probes passed
- `1` — one or more probes failed
- `2` — flag parse error / missing required argument
