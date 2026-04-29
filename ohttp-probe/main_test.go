package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	ohttp "github.com/chris-wood/ohttp-go"
	"github.com/cloudflare/circl/hpke"
)

func newTestGateway(t *testing.T) ohttp.Gateway {
	t.Helper()
	cfg, err := ohttp.NewConfig(0x01, hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	return ohttp.NewDefaultGateway([]ohttp.PrivateConfig{cfg})
}

func marshalKeyConfigList(configs [][]byte) []byte {
	var buf []byte
	for _, c := range configs {
		length := make([]byte, 2)
		binary.BigEndian.PutUint16(length, uint16(len(c)))
		buf = append(buf, length...)
		buf = append(buf, c...)
	}
	return buf
}

func newOHTTPServer(t *testing.T, gw ohttp.Gateway) *httptest.Server {
	t.Helper()
	keyConfigs := gw.MarshalConfigs()

	mux := http.NewServeMux()
	mux.HandleFunc(pathOHTTPKeys, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ohttp-keys")
		_, _ = w.Write(keyConfigs)
	})
	mux.HandleFunc(pathEcho, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body", http.StatusInternalServerError)
			return
		}

		encReq, err := ohttp.UnmarshalEncapsulatedRequest(body)
		if err != nil {
			http.Error(w, "unmarshal request", http.StatusBadRequest)
			return
		}

		plaintext, decCtx, err := gw.DecapsulateRequest(encReq)
		if err != nil {
			http.Error(w, "decapsulate", http.StatusBadRequest)
			return
		}

		encResp, err := decCtx.EncapsulateResponse(plaintext)
		if err != nil {
			http.Error(w, "encapsulate response", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "message/ohttp-res")
		_, _ = w.Write(encResp.Marshal())
	})

	return httptest.NewServer(mux)
}

func TestProbeOHTTPOK(t *testing.T) {
	gw := newTestGateway(t)
	srv := newOHTTPServer(t, gw)
	defer srv.Close()

	payload := []byte("test-payload-123")
	err := probeEcho(context.Background(), srv.Client(), srv.URL, payload, false)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestProbeOHTTPPayloadMismatch(t *testing.T) {
	gw := newTestGateway(t)
	keyConfigs := gw.MarshalConfigs()

	mux := http.NewServeMux()
	mux.HandleFunc(pathOHTTPKeys, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(keyConfigs)
	})
	mux.HandleFunc(pathEcho, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		encReq, _ := ohttp.UnmarshalEncapsulatedRequest(body)
		_, decCtx, _ := gw.DecapsulateRequest(encReq)
		encResp, _ := decCtx.EncapsulateResponse([]byte("wrong-payload"))
		w.Header().Set("Content-Type", "message/ohttp-res")
		_, _ = w.Write(encResp.Marshal())
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	err := probeEcho(context.Background(), srv.Client(), srv.URL, []byte("correct-payload"), false)
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("expected 'mismatch' in error, got: %v", err)
	}
}

func TestProbeOHTTPWrongContentType(t *testing.T) {
	gw := newTestGateway(t)
	keyConfigs := gw.MarshalConfigs()

	mux := http.NewServeMux()
	mux.HandleFunc(pathOHTTPKeys, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(keyConfigs)
	})
	mux.HandleFunc(pathEcho, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("not-ohttp"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	err := probeEcho(context.Background(), srv.Client(), srv.URL, []byte("hello"), false)
	if err == nil {
		t.Fatal("expected content-type error")
	}
	if !strings.Contains(err.Error(), "Content-Type") {
		t.Fatalf("expected Content-Type in error, got: %v", err)
	}
}

func TestProbeOHTTPContentTypeWithParams(t *testing.T) {
	gw := newTestGateway(t)
	srv := newOHTTPServer(t, gw)
	defer srv.Close()

	origHandler := srv.Config.Handler
	mux := http.NewServeMux()
	mux.HandleFunc(pathOHTTPKeys, func(w http.ResponseWriter, r *http.Request) {
		origHandler.ServeHTTP(w, r)
	})
	mux.HandleFunc(pathEcho, func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		origHandler.ServeHTTP(rec, r)
		for k, v := range rec.Header() {
			if k == "Content-Type" {
				w.Header().Set(k, v[0]+"; charset=binary")
			} else {
				w.Header()[k] = v
			}
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
	})

	paramSrv := httptest.NewServer(mux)
	defer paramSrv.Close()

	err := probeEcho(context.Background(), paramSrv.Client(), paramSrv.URL, []byte("hello"), false)
	if err != nil {
		t.Fatalf("expected no error with Content-Type params, got: %v", err)
	}
}

func TestProbeOHTTPNon200Echo(t *testing.T) {
	gw := newTestGateway(t)
	keyConfigs := gw.MarshalConfigs()

	mux := http.NewServeMux()
	mux.HandleFunc(pathOHTTPKeys, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(keyConfigs)
	})
	mux.HandleFunc(pathEcho, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	err := probeEcho(context.Background(), srv.Client(), srv.URL, []byte("hello"), false)
	if err == nil {
		t.Fatal("expected error for non-200 echo")
	}
	if !strings.Contains(err.Error(), "502") {
		t.Fatalf("expected 502 in error, got: %v", err)
	}
}

func TestProbeOHTTPNon200Keys(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc(pathOHTTPKeys, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	err := probeEcho(context.Background(), srv.Client(), srv.URL, []byte("hello"), false)
	if err == nil {
		t.Fatal("expected error for non-200 keys")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Fatalf("expected 404 in error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// probeBHTTP (relay & direct)
// ---------------------------------------------------------------------------

func newRelayServer(t *testing.T, gw ohttp.Gateway, backend http.Handler) (*httptest.Server, *httptest.Server) {
	t.Helper()

	backendSrv := httptest.NewServer(backend)

	keyConfigs := gw.MarshalConfigs()
	keysSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ohttp-keys")
		_, _ = w.Write(keyConfigs)
	}))

	// ohttp.Gateway isn't goroutine-safe (load tests hit a data race
	// inside DecapsulateRequest); serialize access from concurrent
	// request handlers.
	var gwMu sync.Mutex

	relaySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body", http.StatusInternalServerError)
			return
		}

		encReq, err := ohttp.UnmarshalEncapsulatedRequest(body)
		if err != nil {
			http.Error(w, "unmarshal ohttp request", http.StatusBadRequest)
			return
		}

		gwMu.Lock()
		bhttp, decCtx, err := gw.DecapsulateRequest(encReq)
		gwMu.Unlock()
		if err != nil {
			http.Error(w, "decapsulate", http.StatusBadRequest)
			return
		}

		innerReq, err := ohttp.UnmarshalBinaryRequest(bhttp)
		if err != nil {
			http.Error(w, "unmarshal bhttp", http.StatusBadRequest)
			return
		}

		innerReq.URL.Scheme = "http"
		innerReq.URL.Host = backendSrv.Listener.Addr().String()
		innerReq.RequestURI = ""

		innerResp, err := backendSrv.Client().Do(innerReq)
		if err != nil {
			http.Error(w, "backend request failed", http.StatusBadGateway)
			return
		}
		defer func() { _ = innerResp.Body.Close() }()

		bResp := ohttp.CreateBinaryResponse(innerResp)
		bhttpResp, err := bResp.Marshal()
		if err != nil {
			http.Error(w, "marshal bhttp response", http.StatusInternalServerError)
			return
		}

		encResp, err := decCtx.EncapsulateResponse(bhttpResp)
		if err != nil {
			http.Error(w, "encapsulate response", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "message/ohttp-res")
		_, _ = w.Write(encResp.Marshal())
	}))

	t.Cleanup(func() {
		relaySrv.Close()
		keysSrv.Close()
		backendSrv.Close()
	})

	return relaySrv, keysSrv
}

// fetchTestKeys grabs the gateway's key config from a test server. Used by
// probeBHTTP tests, which now take a pre-fetched config (probe.go's runProbe
// fetches keys once up-front and shares across targets).
func fetchTestKeys(t *testing.T, keysURL string) ohttp.PublicConfig {
	t.Helper()
	cfg, err := fetchKeys(context.Background(), http.DefaultClient, keysURL, false)
	if err != nil {
		t.Fatalf("fetch keys: %v", err)
	}
	return cfg
}

func TestProbeRelayOK(t *testing.T) {
	gw := newTestGateway(t)
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	relaySrv, keysSrv := newRelayServer(t, gw, backend)
	cfg := fetchTestKeys(t, keysSrv.URL)

	code, err := probeBHTTP(context.Background(), http.DefaultClient, relaySrv.URL, cfg, "https://example.com/health", false)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
}

func TestProbeRelayOKVerbose(t *testing.T) {
	gw := newTestGateway(t)
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("healthy"))
	})
	relaySrv, keysSrv := newRelayServer(t, gw, backend)
	cfg := fetchTestKeys(t, keysSrv.URL)

	if _, err := probeBHTTP(context.Background(), http.DefaultClient, relaySrv.URL, cfg, "https://example.com/health", true); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestProbeRelayCustomPath(t *testing.T) {
	gw := newTestGateway(t)
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/status" {
			http.Error(w, "wrong path: "+r.URL.Path, http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	relaySrv, keysSrv := newRelayServer(t, gw, backend)
	cfg := fetchTestKeys(t, keysSrv.URL)

	if _, err := probeBHTTP(context.Background(), http.DefaultClient, relaySrv.URL, cfg, "https://example.com/v2/status", false); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestProbeRelayInnerNon2xx(t *testing.T) {
	gw := newTestGateway(t)
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	})
	relaySrv, keysSrv := newRelayServer(t, gw, backend)
	cfg := fetchTestKeys(t, keysSrv.URL)

	code, err := probeBHTTP(context.Background(), http.DefaultClient, relaySrv.URL, cfg, "https://example.com/health", false)
	if err == nil {
		t.Fatal("expected error for non-2xx inner response")
	}
	if code != http.StatusServiceUnavailable {
		t.Fatalf("expected code=503, got %d", code)
	}
	if !strings.Contains(err.Error(), "503") {
		t.Fatalf("expected 503 in error, got: %v", err)
	}
}

func TestProbeRelayRelayNon200(t *testing.T) {
	gw := newTestGateway(t)

	keysSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ohttp-keys")
		_, _ = w.Write(gw.MarshalConfigs())
	}))
	defer keysSrv.Close()

	relaySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Forbidden", http.StatusForbidden)
	}))
	defer relaySrv.Close()
	cfg := fetchTestKeys(t, keysSrv.URL)

	_, err := probeBHTTP(context.Background(), http.DefaultClient, relaySrv.URL, cfg, "https://example.com/health", false)
	if err == nil {
		t.Fatal("expected error for relay 403")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected 403 in error, got: %v", err)
	}
}

func TestProbeRelayWrongContentType(t *testing.T) {
	gw := newTestGateway(t)

	keysSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ohttp-keys")
		_, _ = w.Write(gw.MarshalConfigs())
	}))
	defer keysSrv.Close()

	relaySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("not-ohttp"))
	}))
	defer relaySrv.Close()
	cfg := fetchTestKeys(t, keysSrv.URL)

	_, err := probeBHTTP(context.Background(), http.DefaultClient, relaySrv.URL, cfg, "https://example.com/health", false)
	if err == nil {
		t.Fatal("expected content-type error")
	}
	if !strings.Contains(err.Error(), "Content-Type") {
		t.Fatalf("expected Content-Type in error, got: %v", err)
	}
}

func TestProbeRelayVerifiesTargetHost(t *testing.T) {
	gw := newTestGateway(t)
	var receivedHost string
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHost = r.Host
		w.WriteHeader(http.StatusOK)
	})
	relaySrv, keysSrv := newRelayServer(t, gw, backend)
	cfg := fetchTestKeys(t, keysSrv.URL)

	if _, err := probeBHTTP(context.Background(), http.DefaultClient, relaySrv.URL, cfg, "https://gateway.us.id-infra.worldcoin.dev/health", false); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if receivedHost != "gateway.us.id-infra.worldcoin.dev" {
		t.Fatalf("expected Host=gateway.us.id-infra.worldcoin.dev, got %q", receivedHost)
	}
}

// ---------------------------------------------------------------------------
// fetchKeys
// ---------------------------------------------------------------------------

func TestFetchKeysOK(t *testing.T) {
	gw := newTestGateway(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ohttp-keys")
		_, _ = w.Write(gw.MarshalConfigs())
	}))
	defer srv.Close()

	config, err := fetchKeys(context.Background(), srv.Client(), srv.URL, false)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if config.ID != 0x01 {
		t.Fatalf("expected key_id=1, got %d", config.ID)
	}
}

func TestFetchKeysNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusGone)
	}))
	defer srv.Close()

	_, err := fetchKeys(context.Background(), srv.Client(), srv.URL, false)
	if err == nil {
		t.Fatal("expected error for non-200")
	}
	if !strings.Contains(err.Error(), "410") {
		t.Fatalf("expected 410 in error, got: %v", err)
	}
}

func TestFetchKeysInvalidConfig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not-a-valid-config"))
	}))
	defer srv.Close()

	_, err := fetchKeys(context.Background(), srv.Client(), srv.URL, false)
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
}

func TestFetchKeysContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("should-not-reach"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := fetchKeys(ctx, srv.Client(), srv.URL, false)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

// ---------------------------------------------------------------------------
// unmarshalFirstConfig
// ---------------------------------------------------------------------------

func TestUnmarshalFirstConfigValidSingle(t *testing.T) {
	cfg, err := ohttp.NewConfig(0x01, hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	if err != nil {
		t.Fatal(err)
	}
	pubBytes := cfg.Config().Marshal()
	data := marshalKeyConfigList([][]byte{pubBytes})

	config, err := unmarshalFirstConfig(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if config.ID != 0x01 {
		t.Fatalf("expected key_id=1, got %d", config.ID)
	}
}

func TestUnmarshalFirstConfigSkipsUnsupported(t *testing.T) {
	cfg, err := ohttp.NewConfig(0x02, hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	if err != nil {
		t.Fatal(err)
	}
	validBytes := cfg.Config().Marshal()

	garbage := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	data := marshalKeyConfigList([][]byte{garbage, validBytes})

	config, err := unmarshalFirstConfig(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if config.ID != 0x02 {
		t.Fatalf("expected key_id=2, got %d", config.ID)
	}
}

func TestUnmarshalFirstConfigZeroLength(t *testing.T) {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, 0)

	_, err := unmarshalFirstConfig(data)
	if err == nil {
		t.Fatal("expected error for zero-length entry")
	}
	if !strings.Contains(err.Error(), "zero-length") {
		t.Fatalf("expected 'zero-length' in error, got: %v", err)
	}
}

func TestUnmarshalFirstConfigTruncated(t *testing.T) {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, 100)

	_, err := unmarshalFirstConfig(data)
	if err == nil {
		t.Fatal("expected error for truncated data")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("expected 'truncated' in error, got: %v", err)
	}
}

func TestUnmarshalFirstConfigEmpty(t *testing.T) {
	_, err := unmarshalFirstConfig([]byte{})
	if err == nil {
		t.Fatal("expected error for empty data")
	}
	if !strings.Contains(err.Error(), "no supported") {
		t.Fatalf("expected 'no supported' in error, got: %v", err)
	}
}

func TestReadBodyTooLarge(t *testing.T) {
	big := bytes.Repeat([]byte("x"), maxResponseBody+1)
	resp := &http.Response{Body: io.NopCloser(bytes.NewReader(big))}
	_, err := readBody(resp)
	if err == nil {
		t.Fatal("expected error for oversized body")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("expected 'too large' in error, got: %v", err)
	}
}

func TestReadBodyExactLimit(t *testing.T) {
	data := bytes.Repeat([]byte("x"), maxResponseBody)
	resp := &http.Response{Body: io.NopCloser(bytes.NewReader(data))}
	body, err := readBody(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(body) != maxResponseBody {
		t.Fatalf("expected %d bytes, got %d", maxResponseBody, len(body))
	}
}

func TestValidateURL(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"https://example.com", false},
		{"http://localhost:9090", false},
		{"ftp://example.com", true},
		{"not-a-url", true},
		{"", true},
		{"://missing-scheme", true},
	}

	for _, tt := range tests {
		err := validateURL(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("validateURL(%q) error=%v, wantErr=%v", tt.input, err, tt.wantErr)
		}
	}
}

func TestJoinURL(t *testing.T) {
	got := joinURL("https://example.com", "/health")
	if got != "https://example.com/health" {
		t.Fatalf("expected https://example.com/health, got %s", got)
	}

	got = joinURL("https://example.com/base", "/ohttp-keys")
	if got != "https://example.com/base/ohttp-keys" {
		t.Fatalf("expected https://example.com/base/ohttp-keys, got %s", got)
	}
}
