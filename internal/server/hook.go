package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/North-web-dev/fpkit/data"
	"github.com/North-web-dev/fpkit/internal/web"
)

const (
	hookBodyLimit  = 64 << 10
	hookPerBin     = 100
	hookMaxBins    = 500
	hookGlobalReqs = 5000
	hookDefaultTTL = 2 * time.Hour
)

// HookConfig configures the webhook inspector.
type HookConfig struct {
	Addr    string
	TLSCert string
	TLSKey  string
	NoTLS   bool
	TTL     time.Duration
}

type captured struct {
	Method     string            `json:"method"`
	URL        string            `json:"url"`
	Proto      string            `json:"proto"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	BodySize   int               `json:"body_size"`
	BodyTrunc  bool              `json:"body_truncated"`
	RemoteIP   string            `json:"remote_ip"`
	ReceivedAt time.Time         `json:"received_at"`
	JA4        string            `json:"ja4"`
	JA4Verdict data.Verdict      `json:"ja4_verdict"`
}

// bin holds captured requests. All access is serialized through hookStore.mu,
// so bin has no lock of its own.
type bin struct {
	id      string
	created time.Time
	reqs    []*captured // newest last
	waiters map[chan struct{}]struct{}
}

type hookStore struct {
	mu    sync.Mutex
	bins  map[string]*bin
	ttl   time.Duration
	total int
}

func newHookStore(ttl time.Duration) *hookStore {
	if ttl <= 0 {
		ttl = hookDefaultTTL
	}
	s := &hookStore{bins: map[string]*bin{}, ttl: ttl}
	go s.reap()
	return s
}

func (s *hookStore) reap() {
	t := time.NewTicker(time.Minute)
	for range t.C {
		s.mu.Lock()
		for id, b := range s.bins {
			if time.Since(b.created) > s.ttl {
				s.total -= len(b.reqs)
				delete(s.bins, id)
			}
		}
		if s.total < 0 {
			s.total = 0
		}
		s.mu.Unlock()
	}
}

func (s *hookStore) create() *bin {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.bins) >= hookMaxBins {
		// evict the oldest bin
		var oldestID string
		var oldest time.Time
		for id, b := range s.bins {
			if oldestID == "" || b.created.Before(oldest) {
				oldestID, oldest = id, b.created
			}
		}
		if oldestID != "" {
			s.total -= len(s.bins[oldestID].reqs)
			delete(s.bins, oldestID)
		}
	}
	b := &bin{id: newID(), created: time.Now(), waiters: map[chan struct{}]struct{}{}}
	s.bins[b.id] = b
	return b
}

func (s *hookStore) get(id string) (*bin, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.bins[id]
	return b, ok
}

func (s *hookStore) record(b *bin, c *captured) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b.reqs = append(b.reqs, c)
	s.total++
	if len(b.reqs) > hookPerBin {
		s.total -= len(b.reqs) - hookPerBin
		b.reqs = b.reqs[len(b.reqs)-hookPerBin:]
	}
	for s.total > hookGlobalReqs {
		var victim *bin
		for _, bb := range s.bins {
			if len(bb.reqs) > 0 && (victim == nil || bb.created.Before(victim.created)) {
				victim = bb
			}
		}
		if victim == nil {
			break
		}
		victim.reqs = victim.reqs[1:]
		s.total--
	}
	for ch := range b.waiters {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (s *hookStore) snapshot(b *bin) []*captured {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*captured, len(b.reqs))
	for i, c := range b.reqs {
		out[len(b.reqs)-1-i] = c // newest first
	}
	return out
}

func (s *hookStore) addWaiter(b *bin, ch chan struct{}) {
	s.mu.Lock()
	b.waiters[ch] = struct{}{}
	s.mu.Unlock()
}

func (s *hookStore) removeWaiter(b *bin, ch chan struct{}) {
	s.mu.Lock()
	delete(b.waiters, ch)
	s.mu.Unlock()
}

func newID() string {
	var b [9]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// RunHook starts the webhook/request inspector.
func RunHook(cfg HookConfig) error {
	db, err := data.Load()
	if err != nil {
		return err
	}
	store := newHookStore(cfg.TTL)
	mux := hookMux(db, store)

	if cfg.NoTLS {
		fmt.Fprintf(os.Stderr, "fp hook: listening on http://%s (plain HTTP — JA4 will be n/a)\n", cfg.Addr)
		return http.ListenAndServe(cfg.Addr, mux)
	}
	return serveTLS("hook", cfg.Addr, cfg.TLSCert, cfg.TLSKey, mux)
}

func hookMux(db *data.DB, store *hookStore) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/_fp/app.css", web.CSSHandler)

	mux.HandleFunc("/api/bins", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		b := store.create()
		writeJSON(w, map[string]string{"id": b.id})
	})

	mux.HandleFunc("/b/{id}/", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		b, ok := store.get(id)
		if !ok {
			http.Error(w, "unknown bin", http.StatusNotFound)
			return
		}
		store.record(b, capture(db, r))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"bin":%q}`+"\n", id)
	})
	// capture requests to /b/{id} with no trailing segment too
	mux.HandleFunc("/b/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		b, ok := store.get(id)
		if !ok {
			http.Error(w, "unknown bin", http.StatusNotFound)
			return
		}
		store.record(b, capture(db, r))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"bin":%q}`+"\n", id)
	})

	mux.HandleFunc("/api/bins/{id}/requests", func(w http.ResponseWriter, r *http.Request) {
		b, ok := store.get(r.PathValue("id"))
		if !ok {
			http.Error(w, "unknown bin", http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]any{"id": b.id, "requests": store.snapshot(b)})
	})

	mux.HandleFunc("/i/{id}/stream", func(w http.ResponseWriter, r *http.Request) {
		b, ok := store.get(r.PathValue("id"))
		if !ok {
			http.Error(w, "unknown bin", http.StatusNotFound)
			return
		}
		streamBin(w, r, store, b)
	})

	mux.HandleFunc("/i/{id}", web.PageHandler("hook_bin.html"))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		web.PageHandler("hook_home.html")(w, r)
	})
	return mux
}

func capture(db *data.DB, r *http.Request) *captured {
	body, _ := io.ReadAll(io.LimitReader(r.Body, hookBodyLimit+1))
	trunc := false
	if len(body) > hookBodyLimit {
		body = body[:hookBodyLimit]
		trunc = true
	}
	headers := map[string]string{}
	for k, v := range r.Header {
		headers[k] = strings.Join(v, ", ")
	}
	c := &captured{
		Method:     r.Method,
		URL:        r.URL.String(),
		Proto:      r.Proto,
		Headers:    headers,
		Body:       string(body),
		BodySize:   len(body),
		BodyTrunc:  trunc,
		RemoteIP:   clientIP(r),
		ReceivedAt: time.Now().UTC(),
		JA4:        "n/a",
	}
	if cc, ok := fromRequest(r); ok {
		c.JA4 = cc.JA4()
	}
	c.JA4Verdict = db.Classify(c.JA4)
	return c
}

func streamBin(w http.ResponseWriter, r *http.Request, s *hookStore, b *bin) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	ch := make(chan struct{}, 1)
	s.addWaiter(b, ch)
	defer s.removeWaiter(b, ch)
	fmt.Fprintf(w, "data: ready\n\n")
	fl.Flush()
	ka := time.NewTicker(25 * time.Second)
	defer ka.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ch:
			fmt.Fprintf(w, "data: req\n\n")
			fl.Flush()
		case <-ka.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			fl.Flush()
		}
	}
}
