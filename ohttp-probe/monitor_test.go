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

func TestProbeIterationOK(t *testing.T) {
	gw := newTestGateway(t)
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	relaySrv, keysSrv := newRelayServer(t, gw, backend)

	outcome, code, err := probeIteration(context.Background(), relaySrv.Client(),
		relaySrv.URL, keysSrv.URL, "https://backend.test/health")
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

func TestProbeIterationInnerNon2xxIsTransportErr(t *testing.T) {
	gw := newTestGateway(t)
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	})
	relaySrv, keysSrv := newRelayServer(t, gw, backend)

	outcome, code, err := probeIteration(context.Background(), relaySrv.Client(),
		relaySrv.URL, keysSrv.URL, "https://backend.test/health")
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

func TestProbeIterationRelay5xxIsTransportErr(t *testing.T) {
	keysSrv, relaySrv := relayKeysWithStatus(t, http.StatusBadGateway)

	outcome, _, err := probeIteration(context.Background(), relaySrv.Client(),
		relaySrv.URL, keysSrv.URL, "https://backend.test/health")
	if err == nil {
		t.Fatal("expected error for relay 502")
	}
	if outcome != outcomeTransportErr {
		t.Fatalf("expected outcome=transport_err, got %q", outcome)
	}
}

func TestProbeIterationDecryptErrOnBadContentType(t *testing.T) {
	gw := newTestGateway(t)
	keyConfigs := gw.MarshalConfigs()
	keysSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(keyConfigs)
	}))
	t.Cleanup(keysSrv.Close)

	// Relay returns 200 but with the wrong outer Content-Type — surfaces as
	// errKindDecrypt.
	relaySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("not-ohttp"))
	}))
	t.Cleanup(relaySrv.Close)

	outcome, _, err := probeIteration(context.Background(), relaySrv.Client(),
		relaySrv.URL, keysSrv.URL, "https://backend.test/health")
	if err == nil {
		t.Fatal("expected decrypt error")
	}
	if outcome != outcomeDecryptErr {
		t.Fatalf("expected outcome=decrypt_err, got %q", outcome)
	}
}

func TestProbeIterationKeyFetchFailsAsTransportErr(t *testing.T) {
	keysSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no keys", http.StatusNotFound)
	}))
	t.Cleanup(keysSrv.Close)
	relaySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("relay must not be reached when keys fail")
	}))
	t.Cleanup(relaySrv.Close)

	outcome, _, err := probeIteration(context.Background(), relaySrv.Client(),
		relaySrv.URL, keysSrv.URL, "https://backend.test/health")
	if err == nil {
		t.Fatal("expected error for failed key fetch")
	}
	if outcome != outcomeTransportErr {
		t.Fatalf("expected outcome=transport_err for key fetch failure, got %q", outcome)
	}
}

func TestMonitorMetricsRecord(t *testing.T) {
	m := newMonitorMetrics()
	target := "https://backend.test/health"
	m.preRegisterTarget(target)

	m.record(target, 123*time.Millisecond, outcomeOK)
	m.record(target, 456*time.Millisecond, outcomeTransportErr)
	m.record(target, 789*time.Millisecond, outcomeOK)

	requests := gatherCounterByLabels(t, m.registry, "ohttp_probe_requests_total")
	if got := requests[counterKey(target, outcomeOK)]; got != 2 {
		t.Fatalf("ok counter: want 2, got %v", got)
	}
	if got := requests[counterKey(target, outcomeTransportErr)]; got != 1 {
		t.Fatalf("transport_err counter: want 1, got %v", got)
	}
	if got, ok := requests[counterKey(target, outcomeDecryptErr)]; !ok || got != 0 {
		t.Fatalf("decrypt_err counter: want pre-registered at 0, got value=%v present=%v", got, ok)
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

func TestMonitorMetricsPreRegisterMakesAllOutcomesVisible(t *testing.T) {
	m := newMonitorMetrics()
	target := "https://backend.test/health"
	m.preRegisterTarget(target)

	requests := gatherCounterByLabels(t, m.registry, "ohttp_probe_requests_total")
	for _, outcome := range []string{outcomeOK, outcomeTransportErr, outcomeDecryptErr} {
		got, ok := requests[counterKey(target, outcome)]
		if !ok {
			t.Errorf("outcome %q not pre-registered", outcome)
			continue
		}
		if got != 0 {
			t.Errorf("outcome %q: want 0, got %v", outcome, got)
		}
	}
}

func TestRunMonitorEndToEnd(t *testing.T) {
	gw := newTestGateway(t)
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	relaySrv, keysSrv := newRelayServer(t, gw, backend)

	port, err := freeTCPPort()
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	args := []string{
		"-relay-url", relaySrv.URL,
		"-keys-url", keysSrv.URL,
		"-target-url", "https://backend.test/health",
		"-delay", "20ms",
		"-metrics-addr", addr,
	}
	done := make(chan int, 1)
	go func() { done <- runMonitor(ctx, args) }()

	// Poll /metrics until the counter shows at least one ok outcome.
	deadline := time.Now().Add(2 * time.Second)
	var body string
	for time.Now().Before(deadline) {
		resp, err := http.Get(fmt.Sprintf("http://%s/metrics", addr))
		if err != nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		body = string(raw)
		if strings.Contains(body, `ohttp_probe_requests_total{outcome="ok"`) &&
			!strings.Contains(body, `ohttp_probe_requests_total{outcome="ok",target="https://backend.test/health"} 0`) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(body, "ohttp_probe_requests_total") {
		t.Fatalf("metrics missing counter: %q", body)
	}
	if !strings.Contains(body, `outcome="ok"`) {
		t.Fatalf("metrics missing ok outcome: %q", body)
	}
	if !strings.Contains(body, `outcome="transport_err"`) || !strings.Contains(body, `outcome="decrypt_err"`) {
		t.Fatalf("expected pre-registered transport_err and decrypt_err series in metrics: %q", body)
	}

	resp, err := http.Get(fmt.Sprintf("http://%s/healthz", addr))
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: want 200, got %d", resp.StatusCode)
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("runMonitor exit code: want 0, got %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runMonitor did not return after context cancel")
	}
}

func TestRunMonitorMultiTarget(t *testing.T) {
	gw := newTestGateway(t)
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	relaySrv, keysSrv := newRelayServer(t, gw, backend)

	port, err := freeTCPPort()
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	args := []string{
		"-relay-url", relaySrv.URL,
		"-keys-url", keysSrv.URL,
		"-target-url", "https://backend.test/health",
		"-target-url", "https://other.test/status",
		"-delay", "20ms",
		"-metrics-addr", addr,
	}
	done := make(chan int, 1)
	go func() { done <- runMonitor(ctx, args) }()

	deadline := time.Now().Add(2 * time.Second)
	var body string
	for time.Now().Before(deadline) {
		resp, err := http.Get(fmt.Sprintf("http://%s/metrics", addr))
		if err == nil {
			raw, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			body = string(raw)
			if strings.Contains(body, `target="https://backend.test/health"`) &&
				strings.Contains(body, `target="https://other.test/status"`) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(body, `target="https://backend.test/health"`) {
		t.Errorf("metrics missing first target: %q", body)
	}
	if !strings.Contains(body, `target="https://other.test/status"`) {
		t.Errorf("metrics missing second target: %q", body)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runMonitor did not return after context cancel")
	}
}

func TestRunMonitorFlagValidation(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"missing relay-url", []string{"-keys-url", "https://k", "-target-url", "https://t/p"}},
		{"missing keys-url", []string{"-relay-url", "https://r", "-target-url", "https://t/p"}},
		{"missing target-url", []string{"-relay-url", "https://r", "-keys-url", "https://k"}},
		{"zero delay", []string{
			"-relay-url", "https://r", "-keys-url", "https://k",
			"-target-url", "https://t/p", "-delay", "0",
		}},
		{"invalid url scheme", []string{
			"-relay-url", "ftp://r", "-keys-url", "https://k",
			"-target-url", "https://t/p",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if got := runMonitor(ctx, tt.args); got != 2 {
				t.Errorf("runMonitor exit code: want 2, got %d", got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func counterKey(target, outcome string) string {
	return target + "|" + outcome
}

// gatherCounterByLabels reads the named counter family and returns a map keyed
// by "<target>|<outcome>". Each present series — including pre-registered
// zero-valued ones — appears in the returned map.
func gatherCounterByLabels(t *testing.T, reg *prometheus.Registry, name string) map[string]float64 {
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
			got[labelKey(m, "target", "outcome")] = m.GetCounter().GetValue()
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
		for _, m := range mf.Metric {
			h := m.GetHistogram()
			return h.GetSampleCount(), h.GetSampleSum()
		}
	}
	t.Fatalf("histogram %q not found", name)
	return 0, 0
}

func labelKey(m *dto.Metric, names ...string) string {
	parts := make([]string, 0, len(names))
	for _, name := range names {
		for _, lp := range m.Label {
			if lp.GetName() == name {
				parts = append(parts, lp.GetValue())
				break
			}
		}
	}
	return strings.Join(parts, "|")
}

// relayKeysWithStatus returns (keys, relay) servers where the relay always
// responds with the given status (no OHTTP body) — used to drive transport
// errors without standing up a full backend stack.
func relayKeysWithStatus(t *testing.T, status int) (*httptest.Server, *httptest.Server) {
	t.Helper()
	gw := newTestGateway(t)
	keysSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(gw.MarshalConfigs())
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
