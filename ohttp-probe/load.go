package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	ohttp "github.com/chris-wood/ohttp-go"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

// Error prefixes attached to ohttpRoundTripper failures. The prefixes survive
// http.Client error wrapping so the summary bucketing can scan
// vegeta.Result.Error and keep transport vs decrypt failures distinguishable.
const (
	errPrefixTransport = "ohttp-transport: "
	errPrefixDecrypt   = "ohttp-decrypt: "
)

// prefixForKind maps a doOHTTPRoundTrip error kind to its vegeta-error prefix.
// errKindNone returns "" — caller should only invoke this when err != nil.
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
	PostURL    string
	Mode       bhttpMode
	TargetHost string
	TargetPath string
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

// ohttpRoundTripper turns each outbound inner request into an OHTTP-wrapped
// POST: marshal to BHTTP, HPKE-encapsulate with the pre-fetched key config,
// POST the ciphertext to postURL, and synthesize an *http.Response from the
// decapsulated inner BHTTP response. Transport and decrypt failures surface as
// errors with distinct prefixes; inner non-2xx flows through as a normal
// response so the status code shows up in vegeta.Result.Code.
type ohttpRoundTripper struct {
	inner   *http.Client
	postURL string
	config  ohttp.PublicConfig
}

func (t *ohttpRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	bReq := ohttp.BinaryRequest(*req)
	bhttpBytes, err := bReq.Marshal()
	if err != nil {
		return nil, fmt.Errorf("%smarshal BHTTP: %w", errPrefixDecrypt, err)
	}

	plaintext, kind, err := doOHTTPRoundTrip(req.Context(), t.inner, t.postURL, t.config, bhttpBytes)
	if err != nil {
		return nil, fmt.Errorf("%s%w", prefixForKind(kind), err)
	}

	innerResp, err := ohttp.UnmarshalBinaryResponse(plaintext)
	if err != nil {
		return nil, fmt.Errorf("%sunmarshal BHTTP: %w", errPrefixDecrypt, err)
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

// runLoad drives the BHTTP probe path (relay or direct mode) at a constant
// rate of qps requests per second for the given duration, using vegeta's
// open-model attacker. Keys are fetched once up-front; failure aborts the run.
func runLoad(
	ctx context.Context,
	client *http.Client,
	postURL, keysURL, targetHost, targetPath string,
	mode bhttpMode,
	qps int,
	duration time.Duration,
	verbose bool,
) error {
	fmt.Fprintf(os.Stderr, "load: fetching keys from %s\n", keysURL)
	config, err := fetchKeys(ctx, client, keysURL, verbose)
	if err != nil {
		return fmt.Errorf("key fetch failed (aborting load): %w", err)
	}

	if !strings.HasPrefix(targetPath, "/") {
		targetPath = "/" + targetPath
	}
	innerURL := (&url.URL{Scheme: "https", Host: targetHost, Path: targetPath}).String()

	ohttpClient := &http.Client{
		Timeout: client.Timeout,
		Transport: &ohttpRoundTripper{
			inner:   client,
			postURL: postURL,
			config:  config,
		},
	}

	targeter := vegeta.NewStaticTargeter(vegeta.Target{
		Method: http.MethodGet,
		URL:    innerURL,
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
		PostURL:    postURL,
		Mode:       mode,
		TargetHost: targetHost,
		TargetPath: targetPath,
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
		// Shouldn't happen — ohttpRoundTripper always prefixes its errors.
		// Bucket as transport so unexpected failures aren't silently dropped.
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
	pf("mode:         %s\n", s.Mode)
	pf("post URL:     %s\n", s.PostURL)
	pf("target:       https://%s%s\n", s.TargetHost, s.TargetPath)
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
