package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// newMonitorOpts wires the relay/keys httptest servers from newRelayServer
// into a monitorOpts ready for runMonitor or singleRoundTrip.
func newMonitorOpts(relaySrv, keysSrv *httptest.Server, targetHost string) monitorOpts {
	return monitorOpts{
		PostURL:     relaySrv.URL,
		KeysURL:     keysSrv.URL,
		TargetHost:  targetHost,
		TargetPath:  "/health",
		Mode:        modeRelay,
		Interval:    20 * time.Millisecond,
		MetricsAddr: "127.0.0.1:0",
		Env:         "test",
		Region:      "us",
	}
}

func TestSingleRoundTripOK(t *testing.T) {
	gw := newTestGateway(t)
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	relaySrv, keysSrv := newRelayServer(t, gw, backend)

	opts := newMonitorOpts(relaySrv, keysSrv, "backend.test")
	outcome, code, err := singleRoundTrip(context.Background(), relaySrv.Client(), opts)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if outcome != outcomeOK {
		t.Fatalf("expected outcome=ok, got %q", outcome)
	}
	if code != http.StatusOK {
		t.Fatalf("expected code=200, got %d", code)
	}
}

func TestSingleRoundTripInnerNon2xxIsTransportErr(t *testing.T) {
	gw := newTestGateway(t)
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	})
	relaySrv, keysSrv := newRelayServer(t, gw, backend)

	opts := newMonitorOpts(relaySrv, keysSrv, "backend.test")
	outcome, code, err := singleRoundTrip(context.Background(), relaySrv.Client(), opts)
	if err == nil {
		t.Fatal("expected error for inner 503")
	}
	if outcome != outcomeTransportErr {
		t.Fatalf("expected outcome=transport_err for inner non-2xx, got %q", outcome)
	}
	if code != http.StatusServiceUnavailable {
		t.Fatalf("expected code=503, got %d", code)
	}
}

func TestSingleRoundTripTransportErrOnRelay5xx(t *testing.T) {
	// Relay returns 502; outer round-trip fails before any decapsulation.
	keysSrv, relaySrv := relayWithKeysAndStatus(t, http.StatusBadGateway)
	opts := newMonitorOpts(relaySrv, keysSrv, "backend.test")

	outcome, _, err := singleRoundTrip(context.Background(), relaySrv.Client(), opts)
	if err == nil {
		t.Fatal("expected error for relay 502")
	}
	if outcome != outcomeTransportErr {
		t.Fatalf("expected outcome=transport_err, got %q", outcome)
	}
}

func TestSingleRoundTripDecryptErrOnBadContentType(t *testing.T) {
	gw := newTestGateway(t)
	keyConfigs := gw.MarshalConfigs()

	keysSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(keyConfigs)
	}))
	t.Cleanup(keysSrv.Close)

	// Relay accepts the POST and returns 200 with the wrong Content-Type —
	// doOHTTPRoundTrip surfaces this as errKindDecrypt.
	relaySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("not-ohttp"))
	}))
	t.Cleanup(relaySrv.Close)

	opts := newMonitorOpts(relaySrv, keysSrv, "backend.test")
	outcome, _, err := singleRoundTrip(context.Background(), relaySrv.Client(), opts)
	if err == nil {
		t.Fatal("expected decrypt error")
	}
	if outcome != outcomeDecryptErr {
		t.Fatalf("expected outcome=decrypt_err, got %q", outcome)
	}
}

func TestSingleRoundTripKeyFetchFailsAsTransportErr(t *testing.T) {
	keysSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no keys", http.StatusNotFound)
	}))
	t.Cleanup(keysSrv.Close)
	relaySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("relay must not be reached when keys fail")
	}))
	t.Cleanup(relaySrv.Close)

	opts := newMonitorOpts(relaySrv, keysSrv, "backend.test")
	outcome, _, err := singleRoundTrip(context.Background(), relaySrv.Client(), opts)
	if err == nil {
		t.Fatal("expected error for failed key fetch")
	}
	if outcome != outcomeTransportErr {
		t.Fatalf("expected outcome=transport_err for key fetch failure, got %q", outcome)
	}
}

func TestMonitorMetricsRecordCounterAndHistogram(t *testing.T) {
	opts := monitorOpts{
		Mode:       modeRelay,
		TargetHost: "backend.test",
		Env:        "stage",
		Region:     "eu",
	}
	m := newMonitorMetrics(opts)
	m.record(123*time.Millisecond, outcomeOK)
	m.record(456*time.Millisecond, outcomeTransportErr)
	m.record(789*time.Millisecond, outcomeOK)

	requests := gatherCounter(t, m.registry, "ohttp_probe_requests_total")
	if got := requests[outcomeKey(opts, outcomeOK)]; got != 2 {
		t.Fatalf("ok counter: want 2, got %v", got)
	}
	if got := requests[outcomeKey(opts, outcomeTransportErr)]; got != 1 {
		t.Fatalf("transport_err counter: want 1, got %v", got)
	}
	if got := requests[outcomeKey(opts, outcomeDecryptErr)]; got != 0 {
		t.Fatalf("decrypt_err counter: want 0 (unobserved), got %v", got)
	}

	count, sum := gatherHistogram(t, m.registry, "ohttp_probe_duration_seconds")
	if count != 3 {
		t.Fatalf("histogram count: want 3, got %d", count)
	}
	want := (123 + 456 + 789) * time.Millisecond
	if diff := sum - want.Seconds(); diff < -0.001 || diff > 0.001 {
		t.Fatalf("histogram sum: want ~%v, got %v", want.Seconds(), sum)
	}
}

func TestRunMonitorEndToEnd(t *testing.T) {
	gw := newTestGateway(t)
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	relaySrv, keysSrv := newRelayServer(t, gw, backend)

	opts := newMonitorOpts(relaySrv, keysSrv, "backend.test")
	opts.MetricsAddr = "127.0.0.1:0" // tested via direct registry rather than HTTP

	// Run the loop with a tiny interval; cancel after a few ticks.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Use a fixed metrics port handed via env-style probe to avoid the side
	// server entirely: stand up a custom runMonitor invocation that uses an
	// available port. We just need the loop to record at least one outcome.
	port, err := freeTCPPort()
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	opts.MetricsAddr = fmt.Sprintf("127.0.0.1:%d", port)

	done := make(chan error, 1)
	go func() { done <- runMonitor(ctx, relaySrv.Client(), opts) }()

	// Give the loop time to fire at least the immediate probe + one tick.
	deadline := time.Now().Add(2 * time.Second)
	var body []byte
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/metrics", port))
		if err != nil {
			lastErr = err
			time.Sleep(20 * time.Millisecond)
			continue
		}
		body, err = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err == nil && strings.Contains(string(body), "ohttp_probe_requests_total") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(string(body), "ohttp_probe_requests_total") {
		t.Fatalf("expected metrics body to contain counter; lastErr=%v body=%q", lastErr, string(body))
	}
	if !strings.Contains(string(body), `outcome="ok"`) {
		t.Fatalf("expected ok outcome label in body: %q", string(body))
	}

	// Healthz should respond too.
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", port))
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: want 200, got %d", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runMonitor: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runMonitor did not return after context cancel")
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// outcomeKey produces the canonical map key used by gatherCounter to look up a
// counter row for a given outcome label.
func outcomeKey(opts monitorOpts, outcome string) string {
	return strings.Join([]string{opts.Env, opts.Region, opts.TargetHost, string(opts.Mode), outcome}, "|")
}

func gatherCounter(t *testing.T, reg *prometheus.Registry, name string) map[string]float64 {
	t.Helper()
	got := map[string]float64{}
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.Metric {
			key := labelKey(m)
			got[key] = m.GetCounter().GetValue()
		}
	}
	return got
}

func gatherHistogram(t *testing.T, reg *prometheus.Registry, name string) (uint64, float64) {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		// Single label set in tests.
		for _, m := range mf.Metric {
			h := m.GetHistogram()
			return h.GetSampleCount(), h.GetSampleSum()
		}
	}
	t.Fatalf("histogram %q not found", name)
	return 0, 0
}

func labelKey(m *dto.Metric) string {
	parts := make([]string, 0, len(m.Label))
	// Order matches outcomeKey above: env, region, target, mode, outcome.
	want := []string{"env", "region", "target", "mode", "outcome"}
	for _, name := range want {
		for _, lp := range m.Label {
			if lp.GetName() == name {
				parts = append(parts, lp.GetValue())
				break
			}
		}
	}
	return strings.Join(parts, "|")
}

// relayWithKeysAndStatus returns a (keys, relay) pair where the relay always
// responds with the given status code (no OHTTP body). Used to drive a
// transport-layer error from singleRoundTrip without the full backend stack.
func relayWithKeysAndStatus(t *testing.T, status int) (*httptest.Server, *httptest.Server) {
	t.Helper()
	gw := newTestGateway(t)
	keyConfigs := gw.MarshalConfigs()
	keysSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(keyConfigs)
	}))
	t.Cleanup(keysSrv.Close)

	relaySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "synthetic", status)
	}))
	t.Cleanup(relaySrv.Close)
	return keysSrv, relaySrv
}

func freeTCPPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}
