package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	ohttp "github.com/chris-wood/ohttp-go"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

// Error prefixes survive http.Client wrapping so the summary bucketing can
// scan vegeta.Result.Error to distinguish transport from decrypt failures.
const (
	errPrefixTransport = "ohttp-transport: "
	errPrefixDecrypt   = "ohttp-decrypt: "
)

// prefixForKind maps an error kind to its vegeta-error prefix.
func prefixForKind(kind ohttpErrKind) string {
	switch kind {
	case errKindTransport:
		return errPrefixTransport
	case errKindDecrypt:
		return errPrefixDecrypt
	default:
		return ""
	}
}

type loadSummary struct {
	RelayURL   string
	TargetURL  string
	Duration   time.Duration
	QPS        int
	Elapsed    time.Duration
	Total      uint64
	Success    uint64
	Transport  uint64
	Decrypt    uint64
	Inner      uint64
	Throughput float64
	Latencies  vegeta.LatencyMetrics
}

// ohttpRoundTripper wraps each outbound request in OHTTP, POSTs to relayURL,
// and synthesizes an *http.Response from the decapsulated inner BHTTP. Inner
// non-2xx surfaces in vegeta.Result.Code; transport/decrypt failures get
// prefixed in the error string.
type ohttpRoundTripper struct {
	inner    *http.Client
	relayURL string
	config   ohttp.PublicConfig
}

func (t *ohttpRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	innerResp, kind, err := doBHTTPRoundTrip(req.Context(), t.inner, t.relayURL, t.config, req)
	if err != nil {
		return nil, fmt.Errorf("%s%w", prefixForKind(kind), err)
	}

	var innerBody []byte
	if innerResp.Body != nil {
		innerBody, err = io.ReadAll(io.LimitReader(innerResp.Body, maxResponseBody))
		if err != nil {
			return nil, fmt.Errorf("%sread inner body: %w", errPrefixDecrypt, err)
		}
	}

	synth := &http.Response{
		Status:        fmt.Sprintf("%d %s", innerResp.StatusCode, http.StatusText(innerResp.StatusCode)),
		StatusCode:    innerResp.StatusCode,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        innerResp.Header.Clone(),
		Body:          io.NopCloser(bytes.NewReader(innerBody)),
		ContentLength: int64(len(innerBody)),
		Request:       req,
	}
	return synth, nil
}

// runLoad drives the OHTTP path at constant QPS for a fixed duration.
// Exits 0 on no failures, 1 if any failed, 2 on flag/arg errors.
func runLoad(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("load", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: ohttp-probe load [flags]

Drive a single -target-url through -relay-url at -qps requests per second
for -duration, using vegeta's open-model attacker (workers grow with
offered load, so tail latency isn't masked by a fixed worker pool). Keys
are fetched once up-front. Prints a summary with p50/p95/p99 latency and
per-category error counts.

Flags:
`)
		fs.PrintDefaults()
	}

	relayURL := fs.String("relay-url", "", "URL the OHTTP request is POSTed to. Required.")
	keysURL := fs.String("keys-url", "", "URL of the gateway's OHTTP key config. Required.")
	targetURL := fs.String("target-url", "", "full inner target URL (single-valued in load mode). Required.")
	qps := fs.Int("qps", 0, "target requests per second (required, open-model attacker)")
	duration := fs.Duration("duration", 30*time.Second, "load test duration")
	timeout := fs.Duration("t", 10*time.Second, "HTTP timeout per request")
	verbose := fs.Bool("v", false, "verbose output")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *relayURL == "" || *keysURL == "" || *targetURL == "" {
		fmt.Fprintln(os.Stderr, "error: -relay-url, -keys-url, and -target-url are required")
		fs.Usage()
		return 2
	}
	if *qps < 1 {
		fmt.Fprintf(os.Stderr, "error: -qps must be >= 1 (got %d)\n", *qps)
		return 2
	}
	if *duration <= 0 {
		fmt.Fprintf(os.Stderr, "error: -duration must be > 0 (got %s)\n", *duration)
		return 2
	}
	for _, u := range []string{*relayURL, *keysURL, *targetURL} {
		if err := validateURL(u); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 2
		}
	}

	client := &http.Client{Timeout: *timeout}
	if err := executeLoad(ctx, client, *relayURL, *keysURL, *targetURL, *qps, *duration, *verbose); err != nil {
		fmt.Fprintf(os.Stderr, "\nload: %v\n", err)
		return 1
	}
	return 0
}

// executeLoad runs the vegeta attack. Split from runLoad so tests can drive
// it directly without flag parsing.
func executeLoad(ctx context.Context, client *http.Client, relayURL, keysURL, targetURL string, qps int, duration time.Duration, verbose bool) error {
	fmt.Fprintf(os.Stderr, "load: fetching keys from %s\n", keysURL)
	config, err := fetchKeys(ctx, client, keysURL, verbose)
	if err != nil {
		return fmt.Errorf("key fetch failed (aborting load): %w", err)
	}

	ohttpClient := &http.Client{
		Timeout: client.Timeout,
		Transport: &ohttpRoundTripper{
			inner:    client,
			relayURL: relayURL,
			config:   config,
		},
	}

	targeter := vegeta.NewStaticTargeter(vegeta.Target{
		Method: http.MethodGet,
		URL:    targetURL,
	})
	rate := vegeta.Rate{Freq: qps, Per: time.Second}
	attacker := vegeta.NewAttacker(vegeta.Client(ohttpClient))

	fmt.Fprintf(os.Stderr, "load: %d rps for %s\n", qps, duration)

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			attacker.Stop()
		case <-done:
		}
	}()
	defer close(done)

	var metrics vegeta.Metrics
	var counts bucketCounts
	for res := range attacker.Attack(targeter, rate, duration, "ohttp-probe") {
		metrics.Add(res)
		counts.classify(res)
	}
	metrics.Close()

	summary := loadSummary{
		RelayURL:   relayURL,
		TargetURL:  targetURL,
		Duration:   duration,
		QPS:        qps,
		Elapsed:    metrics.Duration + metrics.Wait,
		Total:      metrics.Requests,
		Success:    counts.success,
		Transport:  counts.transport,
		Decrypt:    counts.decrypt,
		Inner:      counts.inner,
		Throughput: metrics.Throughput,
		Latencies:  metrics.Latencies,
	}
	printLoadSummary(os.Stderr, summary)

	if metrics.Requests == 0 {
		return fmt.Errorf("no requests completed")
	}
	if counts.transport+counts.decrypt+counts.inner > 0 {
		return fmt.Errorf("%d of %d requests failed",
			counts.transport+counts.decrypt+counts.inner, metrics.Requests)
	}
	return nil
}

type bucketCounts struct {
	success, transport, decrypt, inner uint64
}

func (c *bucketCounts) classify(res *vegeta.Result) {
	switch {
	case strings.Contains(res.Error, errPrefixTransport):
		c.transport++
	case strings.Contains(res.Error, errPrefixDecrypt):
		c.decrypt++
	case res.Error != "":
		// Catch-all: ohttpRoundTripper should always prefix; bucket
		// unexpected unprefixed errors as transport.
		c.transport++
	case res.Code < 200 || res.Code >= 300:
		c.inner++
	default:
		c.success++
	}
}

func printLoadSummary(w io.Writer, s loadSummary) {
	pct := func(n uint64) float64 {
		if s.Total == 0 {
			return 0
		}
		return 100 * float64(n) / float64(s.Total)
	}
	pf := func(format string, args ...any) { _, _ = fmt.Fprintf(w, format, args...) }
	pl := func(args ...any) { _, _ = fmt.Fprintln(w, args...) }

	pl()
	pl("=== load summary ===")
	pf("relay URL:    %s\n", s.RelayURL)
	pf("target URL:   %s\n", s.TargetURL)
	pf("rate:         %d rps (target)\n", s.QPS)
	pf("duration:     %s\n", s.Duration)
	pf("elapsed:      %s\n", s.Elapsed.Round(time.Millisecond))
	pl()
	pf("requests:     %d (%.2f rps actual)\n", s.Total, s.Throughput)
	pf("success:      %d (%.2f%%)\n", s.Success, pct(s.Success))
	pf("transport:    %d (%.2f%%) — TCP/TLS/timeout/outer non-200\n", s.Transport, pct(s.Transport))
	pf("decrypt:      %d (%.2f%%) — OHTTP/BHTTP parse/decapsulate\n", s.Decrypt, pct(s.Decrypt))
	pf("inner HTTP:   %d (%.2f%%) — backend non-2xx\n", s.Inner, pct(s.Inner))
	if s.Total > 0 {
		pl()
		pl("latency (all requests):")
		pf("  p50:        %s\n", s.Latencies.P50.Round(time.Millisecond))
		pf("  p95:        %s\n", s.Latencies.P95.Round(time.Millisecond))
		pf("  p99:        %s\n", s.Latencies.P99.Round(time.Millisecond))
		pf("  min:        %s\n", s.Latencies.Min.Round(time.Millisecond))
		pf("  max:        %s\n", s.Latencies.Max.Round(time.Millisecond))
	}
}
