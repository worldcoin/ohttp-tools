package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	ohttp "github.com/chris-wood/ohttp-go"
)

// runProbe parses the probe subcommand's flags and runs one OHTTP round-trip
// per -target-url concurrently through a single -relay-url. Returns process
// exit code: 0 if all targets succeeded, 1 if any failed, 2 on flag errors.
func runProbe(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: ohttp-probe probe [flags]

Send a BHTTP-encoded inner GET to each -target-url through -relay-url. The
relay can be a Cloudflare Privacy Gateway, a gateway's /gateway endpoint, or
any RFC 9458 server. Targets are probed concurrently; exit non-zero if any
fail.

Flags:
`)
		fs.PrintDefaults()
	}

	relayURL := fs.String("relay-url", "", "URL the OHTTP request is POSTed to (Cloudflare relay, gateway /gateway endpoint, or any RFC 9458 server). Required.")
	keysURL := fs.String("keys-url", "", "URL of the gateway's OHTTP key config (e.g. https://<gateway>/ohttp-keys). Required.")
	targets := urlList{}
	fs.Var(&targets, "target-url", "full inner target URL (repeatable). Each becomes one BHTTP GET routed through -relay-url.")
	timeout := fs.Duration("t", 10*time.Second, "HTTP timeout per request")
	verbose := fs.Bool("v", false, "verbose output")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *relayURL == "" || *keysURL == "" || len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "error: -relay-url, -keys-url, and at least one -target-url are required")
		fs.Usage()
		return 2
	}
	for _, t := range targets {
		if err := validateURL(t); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 2
		}
	}
	if err := validateURL(*relayURL); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	client := &http.Client{Timeout: *timeout}

	// Fetch keys once up-front; share across all targets. probe is a
	// one-shot, so any churn from key rotation between iterations isn't
	// a concern (unlike monitor).
	config, err := fetchKeys(ctx, client, *keysURL, *verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		return 1
	}

	type result struct {
		target string
		err    error
		rtt    time.Duration
		code   int
	}
	results := make(chan result, len(targets))

	var wg sync.WaitGroup
	for _, target := range targets {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			start := time.Now()
			code, err := probeBHTTP(ctx, client, *relayURL, config, target, *verbose)
			results <- result{target: target, err: err, rtt: time.Since(start), code: code}
		}(target)
	}
	wg.Wait()
	close(results)

	exit := 0
	for r := range results {
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "FAIL %s (%s): %v\n", r.target, r.rtt.Round(time.Millisecond), r.err)
			exit = 1
			continue
		}
		fmt.Fprintf(os.Stderr, "OK   %s (HTTP %d, %s)\n", r.target, r.code, r.rtt.Round(time.Millisecond))
	}
	return exit
}

// probeBHTTP builds a BHTTP-encoded GET for targetURL, encapsulates it with
// config, POSTs it to relayURL, and decodes the inner response. Returns the
// inner HTTP status code on success; on failure returns the error and a
// best-effort status code (0 if no response was decoded).
func probeBHTTP(ctx context.Context, client *http.Client, relayURL string, config ohttp.PublicConfig, targetURL string, verbose bool) (int, error) {
	innerReq, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return 0, fmt.Errorf("build inner request: %w", err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "     POST %s (Content-Type: message/ohttp-req) for %s\n", relayURL, targetURL)
	}

	innerResp, _, err := doBHTTPRoundTrip(ctx, client, relayURL, config, innerReq)
	if err != nil {
		return 0, err
	}

	var innerBody []byte
	if innerResp.Body != nil {
		innerBody, err = readBody(innerResp)
		if err != nil {
			return innerResp.StatusCode, fmt.Errorf("read inner response body: %w", err)
		}
	}

	if innerResp.StatusCode < 200 || innerResp.StatusCode >= 300 {
		return innerResp.StatusCode, fmt.Errorf("inner response HTTP %d: %s", innerResp.StatusCode, string(innerBody))
	}

	if verbose && len(innerBody) > 0 {
		fmt.Fprintf(os.Stderr, "  body (%s): %s\n", targetURL, string(innerBody))
	}
	return innerResp.StatusCode, nil
}
