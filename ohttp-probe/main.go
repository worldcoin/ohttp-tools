package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
)

const (
	maxResponseBody = 1 << 20 // 1 MB

	pathOHTTPKeys = "/ohttp-keys"
	pathEcho      = "/gateway-echo"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	args := os.Args[2:]
	switch os.Args[1] {
	case "echo":
		os.Exit(runEcho(rootContext(), args))
	case "probe":
		os.Exit(runProbe(rootContext(), args))
	case "load":
		os.Exit(runLoad(rootContext(), args))
	case "monitor":
		os.Exit(runMonitor(rootContext(), args))
	case "-h", "--help", "help":
		usage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `Usage: ohttp-probe <command> [flags]

Probe Oblivious HTTP (RFC 9458) gateways.

Commands:
  echo    POST an HPKE-encrypted payload to the gateway's /gateway-echo
          endpoint and verify the decrypted response. No relay, no backend.
  probe   Send a single OHTTP request through a relay (or directly to a
          gateway) against one or more inner target URLs.
  load    Drive the probe path at a fixed QPS for a fixed duration against
          a single target.
  monitor Long-running probe loop that exposes Prometheus metrics on a
          side server. Intended for in-cluster deployment.

Run "ohttp-probe <command> -h" for command-specific flags.
`)
}

// rootContext returns a context cancelled by SIGINT.
func rootContext() context.Context {
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt)
	return ctx
}

// urlList is a repeatable string flag, accumulating one URL per occurrence.
type urlList []string

func (u *urlList) String() string { return strings.Join(*u, ",") }
func (u *urlList) Set(v string) error {
	if v == "" {
		return fmt.Errorf("empty URL")
	}
	*u = append(*u, v)
	return nil
}

func readBody(resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseBody {
		return nil, fmt.Errorf("response body too large (>%d bytes)", maxResponseBody)
	}

	return body, nil
}

func validateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("invalid URL scheme %q (must be http or https)", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("invalid URL %q: empty host", raw)
	}

	return nil
}

// joinURL appends path to base, normalising slashes.
func joinURL(base, path string) string {
	u, _ := url.Parse(base)
	u = u.JoinPath(path)

	return u.String()
}

func trimRightSlash(s string) string { return strings.TrimRight(s, "/") }
