package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	ohttp "github.com/chris-wood/ohttp-go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Outcome label values recorded on ohttp_probe_requests_total.
const (
	outcomeOK           = "ok"
	outcomeTransportErr = "transport_err"
	outcomeDecryptErr   = "decrypt_err"
)

type monitorMetrics struct {
	registry *prometheus.Registry
	duration *prometheus.HistogramVec
	requests *prometheus.CounterVec
}

func newMonitorMetrics() *monitorMetrics {
	reg := prometheus.NewRegistry()
	duration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ohttp_probe_duration_seconds",
		Help:    "OHTTP probe outer round-trip duration in seconds (excludes key fetch).",
		Buckets: prometheus.DefBuckets,
	}, []string{"target"})
	requests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ohttp_probe_requests_total",
		Help: "Total OHTTP probe iterations, labeled by outcome (ok|transport_err|decrypt_err).",
	}, []string{"target", "outcome"})
	reg.MustRegister(duration, requests)
	return &monitorMetrics{registry: reg, duration: duration, requests: requests}
}

// record observes one round-trip: counter Inc + histogram Observe.
func (m *monitorMetrics) record(target string, elapsed time.Duration, outcome string) {
	m.duration.WithLabelValues(target).Observe(elapsed.Seconds())
	m.requests.WithLabelValues(target, outcome).Inc()
}

// preRegisterTarget materialises all three outcome counters at 0 so absent
// series don't surprise alerting on a fresh probe.
func (m *monitorMetrics) preRegisterTarget(target string) {
	for _, outcome := range []string{outcomeOK, outcomeTransportErr, outcomeDecryptErr} {
		m.requests.WithLabelValues(target, outcome).Add(0)
	}
}

// runMonitor fetches the key config once at startup and runs one probe
// loop per target. Exit codes: 0 on Ctrl-C, 1 on startup/server failure,
// 2 on flag/arg errors. If keys rotate later, probes fail until restart.
func runMonitor(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("monitor", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: ohttp-probe monitor [flags]

Long-running OHTTP probe. Fetches the gateway's key config once at startup,
then on every -delay runs one BHTTP round-trip per -target-url through
-relay-url and records latency and outcome to Prometheus metrics on
-metrics-addr/metrics. Intended for in-cluster deployment with a
Prometheus-compatible scraper picking up the side server.

Flags:
`)
		fs.PrintDefaults()
	}

	relayURL := fs.String("relay-url", "", "URL the OHTTP request is POSTed to. Required.")
	keysURL := fs.String("keys-url", "", "URL of the gateway's OHTTP key config. Required.")
	targets := urlList{}
	fs.Var(&targets, "target-url", "full inner target URL (repeatable). One probe loop per target.")
	delay := fs.Duration("delay", 30*time.Second, "time between probe ticks per target")
	metricsAddr := fs.String("metrics-addr", ":9090", "metrics server bind address")
	timeout := fs.Duration("t", 10*time.Second, "HTTP timeout per request")
	verbose := fs.Bool("v", false, "verbose output (per-iteration stderr log)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *relayURL == "" || *keysURL == "" || len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "error: -relay-url, -keys-url, and at least one -target-url are required")
		fs.Usage()
		return 2
	}
	if *delay <= 0 {
		fmt.Fprintf(os.Stderr, "error: -delay must be > 0 (got %s)\n", *delay)
		return 2
	}
	for _, u := range append([]string{*relayURL, *keysURL}, targets...) {
		if err := validateURL(u); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 2
		}
	}

	keysClient := &http.Client{Timeout: *timeout}
	config, err := fetchKeys(ctx, keysClient, *keysURL, *verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "monitor: startup key fetch failed: %v\n", err)
		return 1
	}

	metrics := newMonitorMetrics()
	for _, target := range targets {
		metrics.preRegisterTarget(target)
	}

	srv, serverErr := startMetricsServer(*metricsAddr, metrics.registry)
	fmt.Fprintf(os.Stderr, "monitor: %d target(s) every %s; metrics on %s/metrics\n",
		len(targets), *delay, *metricsAddr)

	loopCtx, cancelLoops := context.WithCancel(ctx)
	defer cancelLoops()

	var wg sync.WaitGroup
	for _, target := range targets {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			runProbeLoop(loopCtx, *timeout, *relayURL, config, target, *delay, metrics, *verbose)
		}(target)
	}

	exit := 0
	select {
	case <-ctx.Done():
	case err := <-serverErr:
		fmt.Fprintf(os.Stderr, "monitor: metrics server: %v\n", err)
		exit = 1
	}

	cancelLoops()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = srv.Shutdown(shutdownCtx)
	cancel()
	wg.Wait()
	return exit
}

// runProbeLoop fires probes against target on each tick of delay. Owns the
// http.Client so the connection pool is scoped to this goroutine.
func runProbeLoop(
	ctx context.Context,
	timeout time.Duration,
	relayURL string,
	config ohttp.PublicConfig,
	target string,
	delay time.Duration,
	metrics *monitorMetrics,
	verbose bool,
) {
	client := &http.Client{Timeout: timeout}

	probeOnce(ctx, client, relayURL, config, target, metrics, verbose)

	ticker := time.NewTicker(delay)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			probeOnce(ctx, client, relayURL, config, target, metrics, verbose)
		}
	}
}

// probeOnce times one round-trip and records counter + histogram. Inner
// non-2xx maps to transport_err.
func probeOnce(
	ctx context.Context,
	client *http.Client,
	relayURL string,
	config ohttp.PublicConfig,
	target string,
	metrics *monitorMetrics,
	verbose bool,
) {
	if ctx.Err() != nil {
		return
	}

	start := time.Now()
	outcome, code, err := probeIteration(ctx, client, relayURL, config, target)
	elapsed := time.Since(start)
	metrics.record(target, elapsed, outcome)

	if !verbose {
		return
	}
	switch outcome {
	case outcomeOK:
		fmt.Fprintf(os.Stderr, "monitor: %s ok HTTP %d in %s\n",
			target, code, elapsed.Round(time.Millisecond))
	default:
		fmt.Fprintf(os.Stderr, "monitor: %s %s in %s: %v\n",
			target, outcome, elapsed.Round(time.Millisecond), err)
	}
}

// probeIteration runs one BHTTP round-trip and maps the result to an
// outcome label. Caller owns timing; no I/O outside the round-trip.
func probeIteration(ctx context.Context, client *http.Client, relayURL string, config ohttp.PublicConfig, target string) (string, int, error) {
	innerReq, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return outcomeTransportErr, 0, fmt.Errorf("build inner request: %w", err)
	}

	innerResp, kind, err := doBHTTPRoundTrip(ctx, client, relayURL, config, innerReq)
	if err != nil {
		switch kind {
		case errKindDecrypt:
			return outcomeDecryptErr, 0, err
		default:
			return outcomeTransportErr, 0, err
		}
	}
	if innerResp.StatusCode < 200 || innerResp.StatusCode >= 300 {
		return outcomeTransportErr, innerResp.StatusCode, fmt.Errorf("inner HTTP %d", innerResp.StatusCode)
	}
	return outcomeOK, innerResp.StatusCode, nil
}

// startMetricsServer binds /metrics and /healthz on addr. The error channel
// fires once if ListenAndServe returns a non-ErrServerClosed error.
func startMetricsServer(addr string, reg *prometheus.Registry) (*http.Server, <-chan error) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	return srv, errCh
}
