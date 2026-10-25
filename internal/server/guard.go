package server

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/North-web-dev/fpkit/data"
	guard "github.com/North-web-dev/ja4-guard/guard"
)

// GuardConfig configures the fingerprinting reverse proxy.
type GuardConfig struct {
	Addr     string
	Upstream string
	Policy   string // allow | known-browser | deny-list
	TLSCert  string
	TLSKey   string
}

// RunGuard starts a reverse proxy that fingerprints inbound clients (JA4) and
// applies an allow / known-browser / deny-list policy at the edge. The policy
// engine is ja4-guard's; the known-browser allow-list and deny-list are built
// from the embedded dataset.
func RunGuard(cfg GuardConfig) error {
	db, err := data.Load()
	if err != nil {
		return err
	}
	up, err := url.Parse(cfg.Upstream)
	if err != nil || up.Scheme == "" || up.Host == "" {
		return fmt.Errorf("invalid --upstream %q", cfg.Upstream)
	}
	proxy := httputil.NewSingleHostReverseProxy(up)

	var policy *guard.Policy
	switch cfg.Policy {
	case "", "allow":
		policy = &guard.Policy{Default: guard.ActionAllow}
	case "known-browser":
		policy = guard.NewAllowList(browserJA4s(db)...)
	case "deny-list":
		policy = guard.NewDenyList(nonBrowserJA4s(db)...)
	default:
		return fmt.Errorf("unknown --policy %q (allow|known-browser|deny-list)", cfg.Policy)
	}
	logger := log.New(os.Stderr, "fp guard: ", log.LstdFlags)

	h := func(w http.ResponseWriter, r *http.Request) {
		ja4 := "n/a"
		if cc, ok := fromRequest(r); ok {
			ja4 = cc.JA4()
		}
		d := policy.Evaluate(ja4)
		label := "unknown"
		if v := db.Classify(ja4); v.Known {
			label = v.Label
		}
		act := "allow"
		if !d.Allow {
			act = "DENY"
		}
		logger.Printf("%s %s ja4=%s (%s) -> %s [%s]", r.Method, r.URL.Path, ja4, label, act, d.Reason)
		if !d.Allow {
			http.Error(w, "forbidden by fingerprint policy", http.StatusForbidden)
			return
		}
		proxy.ServeHTTP(w, r)
	}

	fmt.Fprintf(os.Stderr, "fp guard: policy=%s upstream=%s\n", cfg.Policy, up)
	return serveTLS("guard", cfg.Addr, cfg.TLSCert, cfg.TLSKey, http.HandlerFunc(h))
}

func browserJA4s(db *data.DB) []string {
	var out []string
	for _, e := range db.Entries {
		if e.Verdict == "browser" || e.Verdict == "browser-engine" {
			out = append(out, e.TLS.JA4)
		}
	}
	return out
}

func nonBrowserJA4s(db *data.DB) []string {
	var out []string
	for _, e := range db.Entries {
		if e.Verdict == "non-browser" {
			out = append(out, e.TLS.JA4)
		}
	}
	return out
}
