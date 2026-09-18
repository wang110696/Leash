// Package proxy implements the Egress Sensor: an HTTP(S) MITM proxy built
// on elazarl/goproxy (ARCHITECTURE.md section 7.2 — don't self-roll
// CONNECT/TLS handling). It only inspects requests, not responses
// (ARCHITECTURE.md 0.2).
package proxy

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"

	"github.com/elazarl/goproxy"

	"github.com/wang110696/Leash/internal/detect"
	"github.com/wang110696/Leash/internal/policy"
	"github.com/wang110696/Leash/internal/store"
)

// maxScanBytes bounds how much of a body is fed to the detector. The full
// body is still forwarded unmodified when allowed — this only limits scan
// cost, it never truncates what's sent upstream (ARCHITECTURE.md 0.2: "body
// 有最大检查体积上限" refers to inspection depth, not to breaking transfers).
const maxScanBytes = 5 << 20 // 5MB

// maxBodyBytes is a hard cap on how much of a request body is ever read
// into memory. Requests larger than this are blocked outright (see the
// comment in inspect()) rather than read without bound.
const maxBodyBytes = 20 << 20 // 20MB

// Proxy is the session-scoped Egress Sensor.
type Proxy struct {
	Listener net.Listener
	server   *goproxy.ProxyHttpServer
	http     *http.Server
	sessID   string
	st       *store.Store
	policy   *policy.Config
}

// New creates a proxy bound to 127.0.0.1:0 (kernel-assigned port) and
// configures it to MITM all CONNECT tunnels using the given local CA.
// cfg is nil-safe: a nil cfg is treated as policy.Default().
func New(sessionID string, st *store.Store, caCertPEM, caKeyPEM []byte, cfg *policy.Config) (*Proxy, error) {
	if cfg == nil {
		cfg = policy.Default()
	}

	cert, err := tls.X509KeyPair(caCertPEM, caKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("load leash CA: %w", err)
	}
	goproxy.GoproxyCa = cert

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("bind proxy listener: %w", err)
	}

	p := &Proxy{Listener: ln, sessID: sessionID, st: st, policy: cfg}

	server := goproxy.NewProxyHttpServer()
	server.Verbose = false
	server.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	server.OnRequest().DoFunc(p.inspect)
	p.server = server
	p.http = &http.Server{Handler: server}

	return p, nil
}

// Addr returns the "host:port" the proxy is listening on.
func (p *Proxy) Addr() string { return p.Listener.Addr().String() }

// Serve runs the proxy until the listener is closed. Intended to be run in
// its own goroutine; per ARCHITECTURE.md 0.7, once this stops, outbound
// HTTP(S) traffic from the session simply fails closed (connection refused)
// — there is no automatic fallback that lets traffic bypass the proxy.
func (p *Proxy) Serve() error {
	return p.http.Serve(p.Listener)
}

func (p *Proxy) Close() error { return p.http.Close() }

func (p *Proxy) inspect(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	var body []byte
	if r.Body != nil {
		// Cap the read rather than io.ReadAll-ing an unbounded body: a
		// multi-GB upload would otherwise be buffered entirely into memory
		// before we ever get to scan it, an easy OOM DoS against the proxy
		// itself (E3 in the v0.1 security review). ARCHITECTURE.md 4.7/7.3
		// says v0.1 doesn't truncate-and-forward a partially-read body
		// (that would corrupt legitimate large requests), so an oversized
		// body is blocked outright instead of silently letting it through
		// unscanned or forwarding a truncated copy.
		b, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
		r.Body.Close()
		if err != nil {
			// Body couldn't be read at all: fail closed rather than forward
			// an unscanned request (ARCHITECTURE.md 0.7/0.9 invariant).
			p.recordAndBlock(r, "network", "body_read_error")
			return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusForbidden,
				"blocked by leash: could not read request body for inspection")
		}
		if len(b) > maxBodyBytes {
			p.recordAndBlock(r, "network", "body_too_large")
			return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusForbidden,
				"blocked by leash: request body exceeds the v0.1 inspection size limit")
		}
		body = b
		r.Body = io.NopCloser(bytes.NewReader(body))
	}

	scanned := body
	if len(scanned) > maxScanBytes {
		scanned = scanned[:maxScanBytes]
	}

	findings := detect.Scan(scanned)

	policyFindings := make([]policy.Finding, len(findings))
	rules := make([]string, len(findings))
	for i, f := range findings {
		policyFindings[i] = policy.Finding{Rule: f.Rule, Confidence: f.Confidence}
		rules[i] = f.Rule
	}

	decision, reason := p.policy.Decide(policyFindings, policy.Request{
		Host:   r.Host,
		Method: r.Method,
		Path:   r.URL.Path,
	})

	severity := "info"
	switch decision {
	case store.Block:
		severity = "high"
	case store.Warn:
		severity = "medium"
	}

	if err := p.st.InsertEvent(p.sessID, "network", severity, decision, map[string]any{
		"host": r.Host,
		// The URL path is intentionally not stored: many APIs embed
		// capability tokens or identifiers directly in the path (e.g.
		// /upload/<token>), which would make the audit log itself a
		// secret-bearing artifact — in tension with the "never store raw
		// secrets" invariant (ARCHITECTURE.md 0.8/0.9, E5 in the v0.1
		// security review).
		"method":        r.Method,
		"bytes":         len(body),
		"matched_rules": rules,
		"reason":        reason,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "leash: failed to record network event: %v\n", err)
	}

	if decision == store.Block {
		fmt.Fprintf(os.Stderr, "leash: BLOCK network %s %s (%s)\n", r.Method, r.Host, reason)
		return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusForbidden,
			fmt.Sprintf("blocked by leash: %s", reason))
	}
	if decision == store.Warn {
		fmt.Fprintf(os.Stderr, "leash: WARN network %s %s (%s)\n", r.Method, r.Host, reason)
	}

	return r, nil
}

// recordAndBlock is used for the fail-closed path where scanning itself
// couldn't happen.
func (p *Proxy) recordAndBlock(r *http.Request, kind, reason string) {
	if err := p.st.InsertEvent(p.sessID, kind, "high", store.Block, map[string]any{
		"host":   r.Host,
		"method": r.Method,
		"reason": reason,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "leash: failed to record event: %v\n", err)
	}
}
