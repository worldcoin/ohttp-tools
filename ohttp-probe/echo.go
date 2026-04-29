package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"
)

// runEcho probes each -gateway-url in sequence. Exits 0 if all succeed,
// 1 if any fail, 2 on flag/arg errors.
func runEcho(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("echo", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: ohttp-probe echo [flags]

POST an HPKE-encrypted payload to each gateway's /gateway-echo endpoint and
verify the decrypted response equals the original. Pure crypto round-trip;
no relay, no inner backend. Requires ALB mTLS temporarily disabled on the
gateway when probing remote production gateways.

Flags:
`)
		fs.PrintDefaults()
	}

	gateways := urlList{}
	fs.Var(&gateways, "gateway-url", "gateway base URL (repeatable). Probe POSTs to <gateway-url>/gateway-echo.")
	payload := fs.String("payload", "hello from ohttp-probe", "payload to echo")
	timeout := fs.Duration("t", 10*time.Second, "HTTP timeout per request")
	verbose := fs.Bool("v", false, "verbose output")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if len(gateways) == 0 {
		fmt.Fprintln(os.Stderr, "error: at least one -gateway-url is required")
		fs.Usage()
		return 2
	}

	client := &http.Client{Timeout: *timeout}
	exit := 0
	for _, gw := range gateways {
		gw = trimRightSlash(gw)
		if err := validateURL(gw); err != nil {
			fmt.Fprintf(os.Stderr, "\n=== %s ===\nFAIL: %v\n", gw, err)
			exit = 1
			continue
		}
		fmt.Fprintf(os.Stderr, "\n=== %s ===\n", gw)
		if err := probeEcho(ctx, client, gw, []byte(*payload), *verbose); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
			exit = 1
		}
	}
	fmt.Fprintln(os.Stderr)
	return exit
}

// probeEcho POSTs an HPKE-encrypted payload to <gateway>/gateway-echo and
// asserts the decapsulated response matches the original.
func probeEcho(ctx context.Context, client *http.Client, gateway string, payload []byte, verbose bool) error {
	config, err := fetchKeys(ctx, client, joinURL(gateway, pathOHTTPKeys), verbose)
	if err != nil {
		return err
	}

	echoURL := joinURL(gateway, pathEcho)
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
