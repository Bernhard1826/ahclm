// Package originprobe provides a controlled TLS origin for certificate rotation
// experiments. The fingerprint belongs to the request's actual TLS connection,
// never to whichever certificate happens to be current when HTTP is handled.
package originprobe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

const Path = "/.well-known/ahclm-origin"

type Rotation struct {
	Fingerprint         string    `json:"target_fingerprint"`
	PreviousFingerprint string    `json:"previous_fingerprint,omitempty"`
	SourceUpdatedAt     time.Time `json:"source_updated_at"`
	SourceTimeBasis     string    `json:"source_time_basis"`
}

type snapshot struct {
	config      *tls.Config
	fingerprint string
}

type connection struct {
	mu          sync.Mutex
	fingerprint string
}

type contextKey struct{}

type Origin struct {
	mu          sync.Mutex
	current     *snapshot
	connections sync.Map
}

func New() *Origin { return &Origin{} }

// Rotate loads and validates both files before replacing the active snapshot.
// Existing connections retain their old identity. Session resumption is disabled
// so a new connection always presents a certificate during a full handshake.
func (o *Origin) Rotate(certFile, keyFile string) (*Rotation, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(cert.Certificate[0])
	fingerprint := hex.EncodeToString(digest[:])
	config := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, SessionTicketsDisabled: true, NextProtos: []string{"http/1.1"}}
	o.mu.Lock()
	defer o.mu.Unlock()
	event := &Rotation{Fingerprint: fingerprint, SourceTimeBasis: "origin_reload", SourceUpdatedAt: time.Now().UTC()}
	if o.current != nil {
		event.PreviousFingerprint = o.current.fingerprint
		if event.PreviousFingerprint == fingerprint {
			return nil, fmt.Errorf("certificate fingerprint has not changed")
		}
	}
	o.current = &snapshot{config: config, fingerprint: fingerprint}
	return event, nil
}

// Server must be served using ServeTLS so ConnContext can bind each request to
// the same transport that GetConfigForClient sees. No TLS-terminating proxy may
// sit between this server and the CDN whose origin handshake is being measured.
func (o *Origin) Server(address string) *http.Server {
	return &http.Server{
		Addr: address, Handler: http.HandlerFunc(o.serveHTTP),
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second,
		TLSConfig:    &tls.Config{MinVersion: tls.VersionTLS12, SessionTicketsDisabled: true, NextProtos: []string{"http/1.1"}, GetConfigForClient: o.configForClient},
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			info := &connection{}
			if tc, ok := conn.(*tls.Conn); ok {
				o.connections.Store(tc.NetConn(), info)
			}
			return context.WithValue(ctx, contextKey{}, info)
		},
		ConnState: func(conn net.Conn, state http.ConnState) {
			if state == http.StateClosed || state == http.StateHijacked {
				if tc, ok := conn.(*tls.Conn); ok {
					o.connections.Delete(tc.NetConn())
				}
			}
		},
	}
}

func (o *Origin) configForClient(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	o.mu.Lock()
	current := o.current
	o.mu.Unlock()
	if current == nil {
		return nil, fmt.Errorf("no origin certificate loaded")
	}
	info, ok := o.connections.Load(hello.Conn)
	if !ok {
		return nil, fmt.Errorf("origin TLS connection is not tracked")
	}
	conn := info.(*connection)
	conn.mu.Lock()
	conn.fingerprint = current.fingerprint
	conn.mu.Unlock()
	return current.config, nil
}

func (o *Origin) serveHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("CDN-Cache-Control", "no-store")
	w.Header().Set("Surrogate-Control", "no-store")
	if r.URL.Path != Path {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	nonce := r.URL.Query().Get("_ahclm_probe")
	if len(nonce) != 32 {
		http.Error(w, "a 32-character hex probe nonce is required", http.StatusBadRequest)
		return
	}
	if _, err := hex.DecodeString(nonce); err != nil {
		http.Error(w, "invalid probe nonce", http.StatusBadRequest)
		return
	}
	info, ok := r.Context().Value(contextKey{}).(*connection)
	if !ok || r.TLS == nil || r.TLS.DidResume {
		http.Error(w, "full TLS handshake required", http.StatusServiceUnavailable)
		return
	}
	info.mu.Lock()
	fingerprint := info.fingerprint
	info.mu.Unlock()
	if fingerprint == "" {
		http.Error(w, "connection certificate is unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("X-AHCLM-Origin-Fingerprint", fingerprint)
	w.Header().Set("X-AHCLM-Probe", nonce)
	w.Header().Set("X-AHCLM-Origin-TLS-Resumed", "false")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"origin_fingerprint": fingerprint, "probe_nonce": nonce, "observed_at": time.Now().UTC()})
}
