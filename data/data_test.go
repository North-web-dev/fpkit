package data

import "testing"

func TestLoadParses(t *testing.T) {
	db, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(db.Entries) < 10 {
		t.Fatalf("expected a populated dataset, got %d entries", len(db.Entries))
	}
	if len(db.Sources) == 0 {
		t.Fatal("dataset must document its sources")
	}
	seen := map[string]bool{}
	for _, e := range db.Entries {
		if e.Name == "" {
			t.Error("entry with empty name")
		}
		if seen[e.Name] {
			t.Errorf("duplicate entry name %q", e.Name)
		}
		seen[e.Name] = true
		if e.TLS.JA4 == "" {
			t.Errorf("entry %q has no JA4", e.Name)
		}
		if e.Verdict == "" {
			t.Errorf("entry %q has no verdict", e.Name)
		}
		if e.Provenance.Source == "" || e.Provenance.Measured == "" {
			t.Errorf("entry %q missing provenance", e.Name)
		}
	}
}

func TestReverseLookupBrowser(t *testing.T) {
	db, _ := Load()
	v := db.Classify("t13d1516h2_8daaf6152771_d8a2da3f94cd")
	if !v.Known || !v.Browser {
		t.Fatalf("expected chrome JA4 to classify as a known browser, got %+v", v)
	}
	if v.Verdict != "browser" {
		t.Errorf("verdict = %q, want browser", v.Verdict)
	}
}

func TestReverseLookupClient(t *testing.T) {
	db, _ := Load()
	v := db.Classify("t13d3113h2_e8f1e7e78f70_ce5650b735ce")
	if !v.Known {
		t.Fatal("expected measured curl JA4 to be known")
	}
	if v.Browser || v.Verdict != "non-browser" {
		t.Errorf("curl JA4 should read as non-browser, got %+v", v)
	}
}

func TestReverseLookupUnknown(t *testing.T) {
	db, _ := Load()
	v := db.Classify("t13d0000h0_000000000000_000000000000")
	if v.Known {
		t.Error("made-up JA4 should be unknown")
	}
	if v.Verdict != "unknown" {
		t.Errorf("verdict = %q, want unknown", v.Verdict)
	}
}

func TestClassifyPlainHTTP(t *testing.T) {
	db, _ := Load()
	for _, s := range []string{"", "n/a"} {
		v := db.Classify(s)
		if v.Known || v.Verdict != "unknown" {
			t.Errorf("empty/na JA4 %q should be unknown, got %+v", s, v)
		}
	}
}

func TestSharedJA4ReturnsAllMatches(t *testing.T) {
	db, _ := Load()
	// python-aiohttp and python-httpx share one measured JA4.
	m := db.LookupJA4("t13d1812h1_85036bcba153_d41ae481755e")
	if len(m) < 2 {
		t.Fatalf("expected shared JA4 to match multiple entries, got %d", len(m))
	}
}
