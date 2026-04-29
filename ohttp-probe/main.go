package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	ohttp "github.com/chris-wood/ohttp-go"
)

const (
	maxResponseBody = 1 << 20 // 1 MB

	pathHealth    = "/health"
	pathOHTTPKeys = "/ohttp-keys"
	pathEcho      = "/gateway-echo"
	pathGateway   = "/gateway"
)

// bhttpMode is the transport the OHTTP-encapsulated BHTTP request rides on.
// Echo mode is served by probeEcho and is not part of this type.
type bhttpMode string

const (
	modeRelay  bhttpMode = "relay"
	modeDirect bhttpMode = "direct"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: ohttp-probe [flags] <url> [url...]

Probe OHTTP gateways by encrypting a test payload and verifying the response.

Modes (selected via -mode):
  echo (default):
    POST an HPKE-encrypted payload to the gateway's /gateway-echo endpoint and
    verify the decrypted response matches. Exercises only the gateway's HPKE
    decrypt/encrypt path — no backend, no relay.

  relay:
    Send a BHTTP-encoded inner request through the Cloudflare Privacy Gateway
    relay. The inner request targets a real backend (-target) and the probe
    verifies the decrypted HTTP response. Requires -keys and -target.

  direct:
    Same as relay mode, but the encrypted request is POSTed straight to the
    gateway ALB's /gateway endpoint, bypassing Cloudflare. Requires -keys and
    -target, plus ALB mTLS temporarily disabled.

Load mode (-load):
  Drives the relay or direct path at -qps requests per second for -duration,
  using vegeta's open-model attacker (workers grow with offered load, so tail
  latency isn't masked by a fixed worker pool). Keys are fetched once up-front.
  Prints a plain-text summary with p50/p95/p99 latency and per-category error
  counts.

Examples:
  ohttp-probe -mode echo https://ohttp-stage.us.id-infra.worldcoin.dev
  ohttp-probe -mode relay -v \
    -keys https://ohttp-keys.us.id-infra.worldcoin.dev/ohttp-keys \
    -target gateway.us.id-infra.worldcoin.dev \
    https://staging.privacy-relay.cloudflare.com/us-world-id-stage
  ohttp-probe -mode direct -v \
    -keys https://ohttp-keys.us.id-infra.worldcoin.dev/ohttp-keys \
    -target indexer.us.id-infra.worldcoin.dev \
    https://ohttp-stage.us.id-infra.worldcoin.dev
  ohttp-probe -mode relay -load -qps 20 -duration 30s \
    -keys https://ohttp-keys.us.id-infra.worldcoin.dev/ohttp-keys \
    -target indexer.us.id-infra.worldcoin.dev \
    https://staging.privacy-relay.cloudflare.com/us-world-id-stage
  ohttp-probe -mode relay -monitor -interval 30s -metrics-addr :9090 \
    -env stage -region us \
    -keys https://ohttp-keys.us.id-infra.worldcoin.dev/ohttp-keys \
    -target indexer.us.id-infra.worldcoin.dev \
    https://staging.privacy-relay.cloudflare.com/us-world-id-stage

Monitor mode (-monitor):
  Long-running probe loop. Refetches keys and runs one relay/direct round-trip
  per -interval, exposing latency (histogram) and outcome counters
  (ok|transport_err|decrypt_err) on -metrics-addr/metrics for Prometheus
  scraping. Use -env and -region to label metrics. Stops on SIGINT.

Flags:
`)
		flag.PrintDefaults()
	}

	mode := flag.String("mode", "echo", "one of: echo | relay | direct")
	payload := flag.String("p", "hello from ohttp-probe", "payload to send via /gateway-echo (echo mode only)")
	timeout := flag.Duration("t", 10*time.Second, "HTTP timeout")
	healthOnly := flag.Bool("health", false, "only check /health endpoint (no OHTTP crypto)")
	keysURL := flag.String("keys", "", "URL to fetch OHTTP keys from (relay and direct modes)")
	target := flag.String("target", "", "target origin for inner BHTTP request (relay and direct modes, e.g. gateway.us.id-infra.worldcoin.dev)")
	targetPath := flag.String("target-path", "/health", "path to request on the target origin (relay and direct modes)")
	verbose := flag.Bool("v", false, "verbose output")
	load := flag.Bool("load", false, "run as load test instead of single probe (relay and direct modes only)")
	duration := flag.Duration("duration", 30*time.Second, "load test duration (load mode)")
	qps := flag.Int("qps", 0, "target requests per second (load mode; required, open-model attacker)")
	monitor := flag.Bool("monitor", false, "run as long-lived monitor that exports Prometheus metrics (relay and direct modes only)")
	interval := flag.Duration("interval", 30*time.Second, "interval between probes (monitor mode)")
	metricsAddr := flag.String("metrics-addr", ":9090", "address for the Prometheus metrics server (monitor mode)")
	envLabel := flag.String("env", "", "value for the env label on exported metrics (monitor mode)")
	regionLabel := flag.String("region", "", "value for the region label on exported metrics (monitor mode)")
	flag.Parse()

	targets := flag.Args()
	if len(targets) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	switch *mode {
	case "echo", "relay", "direct":
	default:
		fmt.Fprintf(os.Stderr, "error: -mode must be one of: echo, relay, direct (got %q)\n", *mode)
		os.Exit(1)
	}
	if (*mode == "relay" || *mode == "direct") && (*keysURL == "" || *target == "") {
		fmt.Fprintf(os.Stderr, "error: -mode %s requires -keys and -target\n", *mode)
		os.Exit(1)
	}

	if *load && *monitor {
		fmt.Fprintf(os.Stderr, "error: -load and -monitor are mutually exclusive\n")
		os.Exit(1)
	}
	if *load {
		if *mode != "relay" && *mode != "direct" {
			fmt.Fprintf(os.Stderr, "error: -load requires -mode relay or direct\n")
			os.Exit(1)
		}
		if len(targets) != 1 {
			fmt.Fprintf(os.Stderr, "error: -load accepts exactly one <url>, got %d\n", len(targets))
			os.Exit(1)
		}
		if *qps < 1 {
			fmt.Fprintf(os.Stderr, "error: -qps is required in load mode and must be >= 1 (got %d)\n", *qps)
			os.Exit(1)
		}
		if *duration <= 0 {
			fmt.Fprintf(os.Stderr, "error: -duration must be > 0 (got %s)\n", *duration)
			os.Exit(1)
		}
	}
	if *monitor {
		if *mode != "relay" && *mode != "direct" {
			fmt.Fprintf(os.Stderr, "error: -monitor requires -mode relay or direct\n")
			os.Exit(1)
		}
		if len(targets) != 1 {
			fmt.Fprintf(os.Stderr, "error: -monitor accepts exactly one <url>, got %d\n", len(targets))
			os.Exit(1)
		}
		if *interval <= 0 {
			fmt.Fprintf(os.Stderr, "error: -interval must be > 0 (got %s)\n", *interval)
			os.Exit(1)
		}
		if *metricsAddr == "" {
			fmt.Fprintf(os.Stderr, "error: -metrics-addr must not be empty\n")
			os.Exit(1)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	client := &http.Client{Timeout: *timeout}

	if *load {
		base := strings.TrimRight(targets[0], "/")
		if err := validateBaseURL(base); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
			os.Exit(1)
		}
		postURL := base
		if *mode == "direct" {
			postURL = joinURL(base, pathGateway)
		}
		err := runLoad(ctx, client, postURL, *keysURL, *target, *targetPath,
			bhttpMode(*mode), *qps, *duration, *verbose)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nload: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *monitor {
		base := strings.TrimRight(targets[0], "/")
		if err := validateBaseURL(base); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
			os.Exit(1)
		}
		postURL := base
		if *mode == "direct" {
			postURL = joinURL(base, pathGateway)
		}
		err := runMonitor(ctx, client, monitorOpts{
			PostURL:     postURL,
			KeysURL:     *keysURL,
			TargetHost:  *target,
			TargetPath:  *targetPath,
			Mode:        bhttpMode(*mode),
			Interval:    *interval,
			MetricsAddr: *metricsAddr,
			Env:         *envLabel,
			Region:      *regionLabel,
			Verbose:     *verbose,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nmonitor: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	exitCode := 0

	for _, base := range targets {
		if ctx.Err() != nil {
			fmt.Fprintf(os.Stderr, "\ninterrupted\n")
			os.Exit(130)
		}

		base = strings.TrimRight(base, "/")
		if err := validateBaseURL(base); err != nil {
			fmt.Fprintf(os.Stderr, "\n=== %s ===\nFAIL: %v\n", base, err)
			exitCode = 1
			continue
		}
		fmt.Fprintf(os.Stderr, "\n=== %s ===\n", base)

		var err error
		switch {
		case *healthOnly:
			err = probeHealth(ctx, client, base, *verbose)
		case *mode == "direct":
			err = probeBHTTP(ctx, client, joinURL(base, pathGateway), *keysURL, *target, *targetPath, modeDirect, *verbose)
		case *mode == "relay":
			err = probeBHTTP(ctx, client, base, *keysURL, *target, *targetPath, modeRelay, *verbose)
		default:
			err = probeEcho(ctx, client, base, []byte(*payload), *verbose)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
			exitCode = 1
		}
	}

	fmt.Fprintln(os.Stderr)
	os.Exit(exitCode)
}

func readBody(resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseBody {
		return nil, fmt.Errorf("response body too large (>%d bytes)", maxResponseBody)
	}

	return body, nil
}

func validateBaseURL(base string) error {
	u, err := url.Parse(base)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", base, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("invalid URL scheme %q (must be http or https)", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("invalid URL %q: empty host", base)
	}

	return nil
}

func joinURL(base, path string) string {
	u, _ := url.Parse(base)
	u = u.JoinPath(path)

	return u.String()
}

func fetchKeys(ctx context.Context, client *http.Client, keysURL string, verbose bool) (ohttp.PublicConfig, error) {
	return fetchKeysSilent(ctx, client, keysURL, verbose, false)
}

// fetchKeysSilent is fetchKeys with an extra knob: when silent is true, all
// progress lines are suppressed regardless of verbose. Monitor mode runs the
// fetch every interval and would otherwise spam stderr with [1/4]/[2/4]
// lines.
func fetchKeysSilent(ctx context.Context, client *http.Client, keysURL string, verbose, silent bool) (ohttp.PublicConfig, error) {
	if verbose && !silent {
		fmt.Fprintf(os.Stderr, "[1/4] GET %s\n", keysURL)
	}

	keysReq, err := http.NewRequestWithContext(ctx, http.MethodGet, keysURL, nil)
	if err != nil {
		return ohttp.PublicConfig{}, fmt.Errorf("build keys request: %w", err)
	}

	keyResp, err := client.Do(keysReq)
	if err != nil {
		return ohttp.PublicConfig{}, fmt.Errorf("fetch keys: %w", err)
	}
	defer func() { _ = keyResp.Body.Close() }()

	keyBytes, err := readBody(keyResp)
	if err != nil {
		return ohttp.PublicConfig{}, fmt.Errorf("read keys response: %w", err)
	}

	if keyResp.StatusCode != http.StatusOK {
		return ohttp.PublicConfig{}, fmt.Errorf("keys endpoint %s returned HTTP %d: %s", keysURL, keyResp.StatusCode, string(keyBytes))
	}
	if !silent {
		fmt.Fprintf(os.Stderr, "[1/4] fetched %d bytes key config\n", len(keyBytes))
	}

	config, err := unmarshalFirstConfig(keyBytes)
	if err != nil {
		return ohttp.PublicConfig{}, fmt.Errorf("parse key config: %w", err)
	}
	if !silent {
		fmt.Fprintf(os.Stderr, "[2/4] parsed OHTTP key config (key_id=%d)\n", config.ID)
	}

	return config, nil
}

func probeHealth(ctx context.Context, client *http.Client, base string, verbose bool) error {
	healthURL := joinURL(base, pathHealth)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		return fmt.Errorf("build health request: %w", err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "GET %s\n", healthURL)
	}

	start := time.Now()
	resp, err := client.Do(req)
	rtt := time.Since(start)
	if err != nil {
		return fmt.Errorf("health request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := readBody(resp)
	if err != nil {
		return fmt.Errorf("read health response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	fmt.Fprintf(os.Stderr, "OK (HTTP %d, RTT %s)\n", resp.StatusCode, rtt.Round(time.Millisecond))
	if verbose && len(body) > 0 {
		fmt.Fprintf(os.Stderr, "  body: %s\n", string(body))
	}

	return nil
}

func probeEcho(ctx context.Context, client *http.Client, base string, payload []byte, verbose bool) error {
	config, err := fetchKeys(ctx, client, joinURL(base, pathOHTTPKeys), verbose)
	if err != nil {
		return err
	}

	echoURL := joinURL(base, pathEcho)
	if verbose {
		fmt.Fprintf(os.Stderr, "     POST %s (Content-Type: message/ohttp-req)\n", echoURL)
	}

	start := time.Now()
	plaintext, _, err := doOHTTPRoundTrip(ctx, client, echoURL, config, payload)
	rtt := time.Since(start)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "[4/4] decrypted response (%d bytes, RTT %s)\n", len(plaintext), rtt.Round(time.Millisecond))

	if !bytes.Equal(plaintext, payload) {
		fmt.Fprintf(os.Stderr, "MISMATCH: sent %q, got %q\n", string(payload), string(plaintext))
		return fmt.Errorf("echo payload mismatch")
	}

	fmt.Fprintf(os.Stderr, "OK: echo matches payload\n")

	if verbose {
		fmt.Fprintf(os.Stderr, "  sent:     %q\n", string(payload))
		fmt.Fprintf(os.Stderr, "  received: %q\n", string(plaintext))
	}

	return nil
}

// probeBHTTP sends an OHTTP-encapsulated BHTTP GET to postURL. postURL is
// either a Cloudflare Privacy Gateway relay URL (mode=modeRelay) or the
// gateway ALB's /gateway endpoint (mode=modeDirect).
func probeBHTTP(ctx context.Context, client *http.Client, postURL, keysURL, targetHost, targetPath string, mode bhttpMode, verbose bool) error {
	config, err := fetchKeys(ctx, client, keysURL, verbose)
	if err != nil {
		return err
	}

	if !strings.HasPrefix(targetPath, "/") {
		targetPath = "/" + targetPath
	}
	targetURL := &url.URL{Scheme: "https", Host: targetHost, Path: targetPath}

	innerReq, err := http.NewRequest(http.MethodGet, targetURL.String(), nil)
	if err != nil {
		return fmt.Errorf("build inner request: %w", err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "     POST %s (Content-Type: message/ohttp-req)\n", postURL)
	}

	start := time.Now()
	innerResp, _, err := doBHTTPRoundTrip(ctx, client, postURL, config, innerReq)
	rtt := time.Since(start)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "[4/4] decrypted BHTTP response (HTTP %d, RTT %s)\n", innerResp.StatusCode, rtt.Round(time.Millisecond))

	var innerBody []byte
	if innerResp.Body != nil {
		innerBody, err = readBody(innerResp)
		if err != nil {
			return fmt.Errorf("read inner response body: %w", err)
		}
	}

	if innerResp.StatusCode < 200 || innerResp.StatusCode >= 300 {
		return fmt.Errorf("inner response HTTP %d: %s", innerResp.StatusCode, string(innerBody))
	}

	fmt.Fprintf(os.Stderr, "OK: %s -> gateway -> %s%s returned HTTP %d\n", mode, targetHost, targetPath, innerResp.StatusCode)

	if verbose && len(innerBody) > 0 {
		fmt.Fprintf(os.Stderr, "  body: %s\n", string(innerBody))
	}

	return nil
}

func unmarshalFirstConfig(data []byte) (ohttp.PublicConfig, error) {
	for len(data) >= 2 {
		configLen := int(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
		if configLen == 0 {
			return ohttp.PublicConfig{}, fmt.Errorf("invalid zero-length key config entry")
		}
		if configLen > len(data) {
			return ohttp.PublicConfig{}, fmt.Errorf("truncated key config list")
		}
		config, err := ohttp.UnmarshalPublicConfig(data[:configLen])
		if err == nil {
			return config, nil
		}
		data = data[configLen:]
	}

	return ohttp.PublicConfig{}, fmt.Errorf("no supported key config found")
}
