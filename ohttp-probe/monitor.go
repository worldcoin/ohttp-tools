package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Outcome label values recorded on ohttp_probe_requests_total.
const (
	outcomeOK           = "ok"
	outcomeTransportErr = "transport_err"
	outcomeDecryptErr   = "decrypt_err"
)

// monitorOpts groups the inputs to runMonitor. It mirrors the relay/direct
// probe arguments plus the monitor-specific knobs (interval, metrics server,
// metric label values).
type monitorOpts struct {
	PostURL     string
	KeysURL     string
	TargetHost  string
	TargetPath  string
	Mode        bhttpMode
	Interval    time.Duration
	MetricsAddr string
	Env         string
	Region      string
	Verbose     bool
}

// monitorMetrics owns the prometheus collectors. They are bound to a single
// label set (env/region/target/mode) so the loop only chooses an outcome.
type monitorMetrics struct {
	registry *prometheus.Registry
	duration prometheus.Observer
	requests *prometheus.CounterVec
	labels   prometheus.Labels
}

func newMonitorMetrics(opts monitorOpts) *monitorMetrics {
	reg := prometheus.NewRegistry()
	durationVec := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ohttp_probe_duration_seconds",
		Help:    "OHTTP probe round-trip duration in seconds, including key fetch.",
		Buckets: prometheus.DefBuckets,
	}, []string{"env", "region", "target", "mode"})
	requestsVec := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ohttp_probe_requests_total",
		Help: "Total OHTTP probe iterations, labeled by outcome (ok|transport_err|decrypt_err).",
	}, []string{"env", "region", "target", "mode", "outcome"})
	reg.MustRegister(durationVec, requestsVec)

	labels := prometheus.Labels{
		"env":    opts.Env,
		"region": opts.Region,
		"target": opts.TargetHost,
		"mode":   string(opts.Mode),
	}

	return &monitorMetrics{
		registry: reg,
		duration: durationVec.With(labels),
		requests: requestsVec,
		labels:   labels,
	}
}

func (m *monitorMetrics) record(elapsed time.Duration, outcome string) {
	m.duration.Observe(elapsed.Seconds())

	lbl := make(prometheus.Labels, len(m.labels)+1)
	for k, v := range m.labels {
		lbl[k] = v
	}
	lbl["outcome"] = outcome
	m.requests.With(lbl).Inc()
}

// runMonitor probes opts.PostURL on a fixed interval, records latency and
// outcome to Prometheus metrics, and serves them on opts.MetricsAddr/metrics.
// Blocks until ctx is cancelled or the metrics server fails to start.
func runMonitor(ctx context.Context, client *http.Client, opts monitorOpts) error {
	if !strings.HasPrefix(opts.TargetPath, "/") {
		opts.TargetPath = "/" + opts.TargetPath
	}

	metrics := newMonitorMetrics(opts)
	srv, serverErr, err := startMetricsServer(opts.MetricsAddr, metrics.registry)
	if err != nil {
		return fmt.Errorf("start metrics server: %w", err)
	}

	fmt.Fprintf(os.Stderr,
		"monitor: %s -> https://%s%s every %s; metrics on %s/metrics\n",
		opts.Mode, opts.TargetHost, opts.TargetPath, opts.Interval, opts.MetricsAddr,
	)

	// Fire one probe immediately so the metric appears without waiting an
	// interval — useful for liveness checks at startup.
	probeOnce(ctx, client, opts, metrics)

	ticker := time.NewTicker(opts.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = srv.Shutdown(shutdownCtx)
			cancel()
			return nil
		case err := <-serverErr:
			return fmt.Errorf("metrics server: %w", err)
		case <-ticker.C:
			probeOnce(ctx, client, opts, metrics)
		}
	}
}

// startMetricsServer binds /metrics (and /healthz for liveness probes) on addr
// and returns the http.Server plus a channel that fires if ListenAndServe
// returns an error other than ErrServerClosed.
func startMetricsServer(addr string, reg *prometheus.Registry) (*http.Server, <-chan error, error) {
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

	return srv, errCh, nil
}

// probeOnce performs one relay/direct round-trip and records the outcome.
// Errors are not returned — they're already captured in metrics. Verbose mode
// prints a one-line summary to stderr.
func probeOnce(ctx context.Context, client *http.Client, opts monitorOpts, metrics *monitorMetrics) {
	if ctx.Err() != nil {
		return
	}

	start := time.Now()
	outcome, statusCode, kindErr := singleRoundTrip(ctx, client, opts)
	elapsed := time.Since(start)
	metrics.record(elapsed, outcome)

	if !opts.Verbose {
		return
	}
	switch outcome {
	case outcomeOK:
		fmt.Fprintf(os.Stderr, "probe ok HTTP %d in %s\n", statusCode, elapsed.Round(time.Millisecond))
	default:
		fmt.Fprintf(os.Stderr, "probe %s in %s: %v\n", outcome, elapsed.Round(time.Millisecond), kindErr)
	}
}

// singleRoundTrip refetches keys and performs one BHTTP round-trip. The
// returned outcome maps doOHTTPRoundTrip's error kind to a metric label and
// buckets inner non-2xx as transport_err — the entry's contracted outcome set
// is ok|transport_err|decrypt_err, so backend-unhealthy responses fold into
// transport (the probe didn't return a healthy result).
func singleRoundTrip(ctx context.Context, client *http.Client, opts monitorOpts) (string, int, error) {
	config, err := fetchKeysSilent(ctx, client, opts.KeysURL, false, true)
	if err != nil {
		return outcomeTransportErr, 0, err
	}

	innerURL := (&url.URL{Scheme: "https", Host: opts.TargetHost, Path: opts.TargetPath}).String()
	innerReq, err := http.NewRequest(http.MethodGet, innerURL, nil)
	if err != nil {
		return outcomeTransportErr, 0, fmt.Errorf("build inner request: %w", err)
	}

	innerResp, kind, err := doBHTTPRoundTrip(ctx, client, opts.PostURL, config, innerReq)
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
