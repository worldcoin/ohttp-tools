package main

import (
	"bytes"
	"context"
	"fmt"
	"mime"
	"net/http"

	ohttp "github.com/chris-wood/ohttp-go"
)

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
