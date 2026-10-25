// Package data embeds and queries the merged fingerprint dataset.
package data

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

//go:embed fingerprints.json
var raw []byte

type TLS struct {
	JA3     string `json:"ja3"`
	JA3Hash string `json:"ja3_hash"`
	JA4     string `json:"ja4"`
}

type HTTP2 struct {
	AkamaiFingerprint string `json:"akamai_fingerprint"`
	AkamaiHash        string `json:"akamai_hash"`
}

type Provenance struct {
	Source   string `json:"source"`
	Method   string `json:"method"`
	Measured string `json:"measured"`
}

type Entry struct {
	Name              string     `json:"name"`
	Kind              string     `json:"kind"`     // browser | engine | client
	Category          string     `json:"category"` // browser | browser-engine | tool | library
	Verdict           string     `json:"verdict"`  // browser | browser-engine | non-browser
	Label             string     `json:"label"`
	UserAgent         string     `json:"user_agent,omitempty"`
	UTLSClientHelloID string     `json:"utls_client_hello_id,omitempty"`
	TLS               TLS        `json:"tls"`
	HTTP2             HTTP2      `json:"http2"`
	JA4H              string     `json:"ja4h,omitempty"`
	Provenance        Provenance `json:"provenance"`
}

type Source struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	Role string `json:"role"`
}

type DB struct {
	SchemaVersion string   `json:"schema_version"`
	Generated     string   `json:"generated"`
	Note          string   `json:"note"`
	Sources       []Source `json:"sources"`
	Entries       []Entry  `json:"entries"`
}

var loaded *DB

// Load parses the embedded dataset once and caches it.
func Load() (*DB, error) {
	if loaded != nil {
		return loaded, nil
	}
	var db DB
	if err := json.Unmarshal(raw, &db); err != nil {
		return nil, fmt.Errorf("data: parsing embedded dataset: %w", err)
	}
	if len(db.Entries) == 0 {
		return nil, fmt.Errorf("data: embedded dataset has no entries")
	}
	loaded = &db
	return loaded, nil
}

// Get returns the entry with the given name.
func (db *DB) Get(name string) (Entry, bool) {
	for _, e := range db.Entries {
		if e.Name == name {
			return e, true
		}
	}
	return Entry{}, false
}

// LookupJA4 returns every entry whose JA4 equals ja4.
func (db *DB) LookupJA4(ja4 string) []Entry {
	ja4 = strings.TrimSpace(ja4)
	var out []Entry
	for _, e := range db.Entries {
		if e.TLS.JA4 == ja4 {
			out = append(out, e)
		}
	}
	return out
}

// Names returns all entry names, sorted.
func (db *DB) Names() []string {
	out := make([]string, 0, len(db.Entries))
	for _, e := range db.Entries {
		out = append(out, e.Name)
	}
	sort.Strings(out)
	return out
}

// Verdict is a human-readable reverse-lookup result for one JA4.
type Verdict struct {
	JA4     string  `json:"ja4"`
	Known   bool    `json:"known"`
	Label   string  `json:"label"`   // e.g. "Google Chrome 131 (Windows)" or "unknown"
	Verdict string  `json:"verdict"` // browser | browser-engine | non-browser | unknown
	Browser bool    `json:"browser"` // true for a real browser
	Matches []Entry `json:"matches"` // all entries sharing this JA4
	Summary string  `json:"summary"` // one-line shareable string
}

// Classify reverse-looks-up a JA4 and returns a shareable verdict.
func (db *DB) Classify(ja4 string) Verdict {
	ja4 = strings.TrimSpace(ja4)
	v := Verdict{JA4: ja4, Verdict: "unknown", Label: "unknown"}
	if ja4 == "" || ja4 == "n/a" {
		v.Summary = "no TLS fingerprint (plain HTTP) — n/a"
		return v
	}
	m := db.LookupJA4(ja4)
	if len(m) == 0 {
		v.Summary = ja4 + " — unknown client (not in dataset)"
		return v
	}
	v.Known = true
	v.Matches = m
	labels := make([]string, 0, len(m))
	for _, e := range m {
		labels = append(labels, e.Label)
	}
	v.Label = strings.Join(labels, " / ")
	v.Verdict = m[0].Verdict
	switch v.Verdict {
	case "browser":
		v.Browser = true
		v.Summary = "You look like: " + v.Label + " — browser"
	case "browser-engine":
		v.Summary = "You look like: " + v.Label + " — browser engine"
	default:
		v.Summary = "You look like: " + v.Label + " — not a browser"
	}
	return v
}
