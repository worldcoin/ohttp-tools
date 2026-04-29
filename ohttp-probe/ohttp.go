package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"mime"
	"net/http"
	"os"

	ohttp "github.com/chris-wood/ohttp-go"
)

// fetchKeys GETs keysURL, parses the first supported HPKE config from the
// returned key config list, and returns it. Verbose mode prints the GET
// stage and (always-on) byte/key-id lines for diagnostic output during
// single-shot CLI runs.
func fetchKeys(ctx context.Context, client *http.Client, keysURL string, verbose bool) (ohttp.PublicConfig, error) {
	if verbose {
		fmt.Fprintf(os.Stderr, "[1/4] GET %s\n", keysURL)
	}

	keysReq, err := http.NewRequestWithContext(ctx, http.MethodGet, keysURL, nil)
	if err != nil {
		return ohttp.PublicConfig{}, fmt.Errorf("build keys request: %w", err)
	}

	keyResp, err := client.Do(keysReq)
	if err != nil {
		return ohttp.PublicConfig{}, fmt.Errorf("fetch keys: %w", err)
	}
	defer func() { _ = keyResp.Body.Close() }()

	keyBytes, err := readBody(keyResp)
	if err != nil {
		return ohttp.PublicConfig{}, fmt.Errorf("read keys response: %w", err)
	}
	if keyResp.StatusCode != http.StatusOK {
		return ohttp.PublicConfig{}, fmt.Errorf("keys endpoint %s returned HTTP %d: %s", keysURL, keyResp.StatusCode, string(keyBytes))
	}
	fmt.Fprintf(os.Stderr, "[1/4] fetched %d bytes key config\n", len(keyBytes))

	config, err := unmarshalFirstConfig(keyBytes)
	if err != nil {
		return ohttp.PublicConfig{}, fmt.Errorf("parse key config: %w", err)
	}
	fmt.Fprintf(os.Stderr, "[2/4] parsed OHTTP key config (key_id=%d)\n", config.ID)

	return config, nil
}

// unmarshalFirstConfig parses a length-prefixed OHTTP key config list and
// returns the first entry the chris-wood/ohttp-go decoder accepts. RFC 9458
// servers can advertise multiple configs (different ciphersuites); pick the
// first one we know how to use.
func unmarshalFirstConfig(data []byte) (ohttp.PublicConfig, error) {
	for len(data) >= 2 {
		configLen := int(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
		if configLen == 0 {
			return ohttp.PublicConfig{}, fmt.Errorf("invalid zero-length key config entry")
		}
		if configLen > len(data) {
			return ohttp.PublicConfig{}, fmt.Errorf("truncated key config list")
		}
		config, err := ohttp.UnmarshalPublicConfig(data[:configLen])
		if err == nil {
			return config, nil
		}
		data = data[configLen:]
	}

	return ohttp.PublicConfig{}, fmt.Errorf("no supported key config found")
}

// ohttpErrKind classifies failures from doOHTTPRoundTrip so callers can route
// them. transport covers TCP/TLS/timeout/outer-non-200; decrypt covers
// encapsulate/Content-Type/unmarshal/decapsulate. errKindNone pairs with a nil
// error.
type ohttpErrKind int

const (
	errKindNone ohttpErrKind = iota
	errKindTransport
	errKindDecrypt
)

// doOHTTPRoundTrip encapsulates plaintext under config, POSTs the ciphertext
// to postURL with Content-Type: message/ohttp-req, validates the outer
// response (HTTP 200 + Content-Type: message/ohttp-res), and returns the
// decapsulated inner plaintext. BHTTP marshal/unmarshal stays in callers; the
// helper is silent (no logging) so callers can print their own stage messages.
func doOHTTPRoundTrip(
	ctx context.Context,
	client *http.Client,
	postURL string,
	config ohttp.PublicConfig,
	plaintext []byte,
) ([]byte, ohttpErrKind, error) {
	ohttpClient := ohttp.NewDefaultClient(config)
	encReq, encCtx, err := ohttpClient.EncapsulateRequest(plaintext)
	if err != nil {
		return nil, errKindDecrypt, fmt.Errorf("encapsulate: %w", err)
	}
	ciphertext := encReq.Marshal()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, postURL, bytes.NewReader(ciphertext))
	if err != nil {
		return nil, errKindTransport, fmt.Errorf("build POST: %w", err)
	}
	req.Header.Set("Content-Type", "message/ohttp-req")

	resp, err := client.Do(req)
	if err != nil {
		return nil, errKindTransport, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := readBody(resp)
	if err != nil {
		return nil, errKindTransport, fmt.Errorf("read outer body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errKindTransport, fmt.Errorf("POST %s returned HTTP %d: %s", postURL, resp.StatusCode, string(body))
	}

	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if mediaType != "message/ohttp-res" {
		return nil, errKindDecrypt, fmt.Errorf("unexpected Content-Type: %s", resp.Header.Get("Content-Type"))
	}

	encapResp, err := ohttp.UnmarshalEncapsulatedResponse(body)
	if err != nil {
		return nil, errKindDecrypt, fmt.Errorf("unmarshal encapsulated response: %w", err)
	}
	innerPlaintext, err := encCtx.DecapsulateResponse(encapResp)
	if err != nil {
		return nil, errKindDecrypt, fmt.Errorf("decapsulate response: %w", err)
	}

	return innerPlaintext, errKindNone, nil
}

// doBHTTPRoundTrip marshals innerReq to BHTTP, performs the OHTTP round-trip
// via doOHTTPRoundTrip, and unmarshals the inner response. BHTTP marshal and
// unmarshal failures are classified as decrypt.
func doBHTTPRoundTrip(
	ctx context.Context,
	client *http.Client,
	postURL string,
	config ohttp.PublicConfig,
	innerReq *http.Request,
) (*http.Response, ohttpErrKind, error) {
	bReq := ohttp.BinaryRequest(*innerReq)
	bhttpBytes, err := bReq.Marshal()
	if err != nil {
		return nil, errKindDecrypt, fmt.Errorf("marshal BHTTP request: %w", err)
	}

	plaintext, kind, err := doOHTTPRoundTrip(ctx, client, postURL, config, bhttpBytes)
	if err != nil {
		return nil, kind, err
	}

	innerResp, err := ohttp.UnmarshalBinaryResponse(plaintext)
	if err != nil {
		return nil, errKindDecrypt, fmt.Errorf("unmarshal BHTTP response: %w", err)
	}

	return innerResp, errKindNone, nil
}
