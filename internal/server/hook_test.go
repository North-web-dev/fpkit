package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/North-web-dev/fpkit/data"
)

func testDB(t *testing.T) *data.DB {
	t.Helper()
	db, err := data.Load()
	if err != nil {
		t.Fatalf("data.Load: %v", err)
	}
	return db
}

func TestHookCaptureRoundtrip(t *testing.T) {
	db := testDB(t)
	store := newHookStore(0)
	b := store.create()
	payload := `<script>alert('xss')</script>`
	r := httptest.NewRequest(http.MethodPost, "/b/"+b.id+"/webhook?x=1", strings.NewReader(payload))
	r.Header.Set("X-Test", "hello")
	store.record(b, capture(db, r))

	got := store.snapshot(b)
	if len(got) != 1 {
		t.Fatalf("want 1 captured request, got %d", len(got))
	}
	c := got[0]
	if c.Method != "POST" {
		t.Errorf("method = %q", c.Method)
	}
	if c.Body != payload {
		t.Errorf("body not preserved verbatim: %q", c.Body)
	}
	if c.Headers["X-Test"] != "hello" {
		t.Errorf("header lost: %v", c.Headers)
	}
	if c.JA4 != "n/a" {
		t.Errorf("plain-HTTP capture should have JA4 n/a, got %q", c.JA4)
	}
}

func TestRingBufferEviction(t *testing.T) {
	db := testDB(t)
	store := newHookStore(0)
	b := store.create()
	for i := 0; i < hookPerBin+25; i++ {
		r := httptest.NewRequest(http.MethodGet, "/b/"+b.id+"/n", nil)
		r.Header.Set("Seq", string(rune('A'+i%26)))
		store.record(b, capture(db, r))
	}
	got := store.snapshot(b)
	if len(got) != hookPerBin {
		t.Fatalf("ring buffer should cap at %d, got %d", hookPerBin, len(got))
	}
	// snapshot is newest-first; the final recorded request must be first.
	if store.total != hookPerBin {
		t.Errorf("store.total = %d, want %d", store.total, hookPerBin)
	}
}

func TestHookXSSResponseIsJSON(t *testing.T) {
	db := testDB(t)
	store := newHookStore(0)
	srv := httptest.NewServer(hookMux(db, store))
	defer srv.Close()

	// create a bin
	resp, err := http.Post(srv.URL+"/api/bins", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	var created struct{ ID string }
	json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	if created.ID == "" {
		t.Fatal("no bin id returned")
	}

	// send a hostile body + header
	evil := `</script><img src=x onerror=alert(1)>`
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/b/"+created.ID+"/hook", strings.NewReader(evil))
	req.Header.Set("X-Evil", `"><svg onload=alert(1)>`)
	if _, err := http.DefaultClient.Do(req); err != nil {
		t.Fatal(err)
	}

	// the data API must return JSON (not HTML), with the payload safely encoded
	r2, err := http.Get(srv.URL + "/api/bins/" + created.ID + "/requests")
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Body.Close()
	if ct := r2.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("data API content-type = %q, want application/json", ct)
	}
	raw, _ := io.ReadAll(r2.Body)
	// valid JSON round-trips the hostile strings as data
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("data API did not return valid JSON: %v", err)
	}
	if !bytes.Contains(raw, []byte(`onerror`)) {
		t.Error("expected the captured body to be present as JSON data")
	}

	// the bin viewer page is static HTML and does not reflect user input
	r3, _ := http.Get(srv.URL + "/i/" + created.ID)
	page, _ := io.ReadAll(r3.Body)
	r3.Body.Close()
	if bytes.Contains(page, []byte(evil)) {
		t.Error("bin viewer HTML must not embed captured content server-side")
	}
	if !bytes.Contains(page, []byte("textContent")) {
		t.Error("bin viewer should render captured content via textContent (escaped)")
	}
}
