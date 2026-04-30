# ohttp-tools

Tooling and container images for running [Oblivious HTTP (RFC 9458)](https://www.rfc-editor.org/rfc/rfc9458.html)
gateways. Currently used by World ID; structured to be reusable for any service
that adopts OHTTP.

## Contents

- [`ohttp-probe/`](./ohttp-probe) — Go CLI for probing and load-testing OHTTP
  gateways. See [`ohttp-probe/README.md`](./ohttp-probe/README.md) for usage.
- `.github/workflows/build-ohttp-gateway.yml` — repackages
  [`cloudflare/privacy-gateway-server-go`](https://github.com/cloudflare/privacy-gateway-server-go)
  at a pinned version into an org-published image.
- `.github/workflows/build-ohttp-probe.yml` — builds and publishes the probe
  image from this repo.

## Published images

Both images are public on GHCR (anonymous pull works):

| Image | Source | Tags |
|---|---|---|
| `ghcr.io/worldcoin/ohttp-tools/ohttp-gateway` | `cloudflare/privacy-gateway-server-go` (pinned via `VERSION` in the build workflow) | `latest`, `<version>` (e.g. `v0.0.3`) |
| `ghcr.io/worldcoin/ohttp-tools/ohttp-probe` | this repo, `ohttp-probe/Dockerfile` | `sha-<full-sha>` |

Both images are `linux/amd64` only.

To bump the gateway version, edit `VERSION` in
`.github/workflows/build-ohttp-gateway.yml` and merge — the workflow rebuilds
on `main`.

## Deployment

This repo holds tooling only. Cluster wiring lives with the consuming service:

- **Terraform** (ALB, ACM, mTLS, Datadog monitors) — `worldcoin/infrastructure`,
  under `world-id-protocol/` and `datadog/protocol/`.
- **Helm values + deploy workflows** — `worldcoin/world-id-protocol-deploy`,
  under `deploy/`.

## Local development

The probe is a self-contained Go module — see
[`ohttp-probe/README.md`](./ohttp-probe/README.md) for build and command
reference.
