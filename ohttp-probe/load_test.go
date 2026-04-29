package main

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	vegeta "github.com/tsenart/vegeta/v12/lib"
)

func TestClassifyBuckets(t *testing.T) {
	tests := []struct {
		name string
		res  *vegeta.Result
		want string
	}{
		{"transport", &vegeta.Result{Error: errPrefixTransport + "dial: refused"}, "transport"},
		{"decrypt", &vegeta.Result{Error: errPrefixDecrypt + "bad content-type"}, "decrypt"},
		{"wrapped transport", &vegeta.Result{Error: "Post \"https://x\": " + errPrefixTransport + "EOF"}, "transport"},
		{"unknown error", &vegeta.Result{Error: "something else"}, "transport"},
		{"inner 500", &vegeta.Result{Code: 500}, "inner"},
		{"inner 404", &vegeta.Result{Code: 404}, "inner"},
		{"success 200", &vegeta.Result{Code: 200}, "success"},
		{"success 204", &vegeta.Result{Code: 204}, "success"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c bucketCounts
			c.classify(tt.res)
			var got string
			switch {
			case c.transport == 1:
				got = "transport"
			case c.decrypt == 1:
				got = "decrypt"
			case c.inner == 1:
				got = "inner"
			case c.success == 1:
				got = "success"
			}
			if got != tt.want {
				t.Errorf("classify bucket = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPrintLoadSummaryBasic(t *testing.T) {
	s := loadSummary{
		RelayURL:   "https://relay.example.com/foo",
		TargetURL:  "https://indexer.us.example.com/health",
		Duration:   10 * time.Second,
		QPS:        20,
		Elapsed:    10 * time.Second,
		Total:      100,
		Success:    95,
		Inner:      5,
		Throughput: 9.5,
		Latencies: vegeta.LatencyMetrics{
			P50: 50 * time.Millisecond,
			P95: 90 * time.Millisecond,
			P99: 95 * time.Millisecond,
			Min: 1 * time.Millisecond,
			Max: 100 * time.Millisecond,
		},
	}
	var buf bytes.Buffer
	printLoadSummary(&buf, s)
	out := buf.String()
	for _, want := range []string{
		"target URL:   https://indexer.us.example.com/health",
		"rate:         20 rps",
		"requests:     100",
		"success:      95",
		"inner HTTP:   5",
		"p50:",
		"p95:",
		"p99:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q\n---\n%s", want, out)
		}
	}
}

func TestPrintLoadSummaryNoRequests(t *testing.T) {
	s := loadSummary{
		RelayURL:  "https://relay.example.com/foo",
		TargetURL: "https://target.example.com/health",
		Duration:  time.Second,
		QPS:       10,
		Elapsed:   time.Second,
	}
	var buf bytes.Buffer
	printLoadSummary(&buf, s)
	out := buf.String()
	if strings.Contains(out, "p50:") {
		t.Errorf("expected no latency block when no requests, got:\n%s", out)
	}
	if !strings.Contains(out, "requests:     0") {
		t.Errorf("expected zero request count in summary, got:\n%s", out)
	}
}

func TestExecuteLoadIntegration(t *testing.T) {
	gw := newTestGateway(t)
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	relaySrv, keysSrv := newRelayServer(t, gw, backend)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := executeLoad(ctx, http.DefaultClient, relaySrv.URL, keysSrv.URL,
		"https://example.com/health", 20, 300*time.Millisecond, false)
	if err != nil {
		t.Fatalf("executeLoad: unexpected error: %v", err)
	}
}

func TestExecuteLoadRate(t *testing.T) {
	gw := newTestGateway(t)
	var served int32
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&served, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	relaySrv, keysSrv := newRelayServer(t, gw, backend)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// 10 rps for 500ms -> ~5 requests. vegeta's open-model attacker fires
	// on a constant-rate schedule; accept a wide 2-15 band for jitter.
	err := executeLoad(ctx, http.DefaultClient, relaySrv.URL, keysSrv.URL,
		"https://example.com/health", 10, 500*time.Millisecond, false)
	if err != nil {
		t.Fatalf("executeLoad: unexpected error: %v", err)
	}
	n := atomic.LoadInt32(&served)
	if n < 2 || n > 15 {
		t.Errorf("served = %d, expected ~5 at 10 rps for 500ms", n)
	}
}

func TestExecuteLoadInnerHTTPErrors(t *testing.T) {
	gw := newTestGateway(t)
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	})
	relaySrv, keysSrv := newRelayServer(t, gw, backend)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := executeLoad(ctx, http.DefaultClient, relaySrv.URL, keysSrv.URL,
		"https://example.com/health", 20, 200*time.Millisecond, false)
	if err == nil {
		t.Fatal("expected non-nil error when all requests return inner 5xx")
	}
	if !strings.Contains(err.Error(), "failed") {
		t.Errorf("expected 'failed' in error, got %v", err)
	}
}

func TestExecuteLoadKeysUnreachable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err := executeLoad(ctx, http.DefaultClient, "http://127.0.0.1:1", "http://127.0.0.1:1/keys",
		"https://example.com/health", 10, 200*time.Millisecond, false)
	if err == nil {
		t.Fatal("expected key fetch to fail")
	}
	if !strings.Contains(err.Error(), "key fetch failed") {
		t.Errorf("expected 'key fetch failed' in error, got %v", err)
	}
}
