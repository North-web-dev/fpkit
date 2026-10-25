// Package fetch implements fp get (browser-impersonating fetch) and fp check
// (CI drift detection) on top of impersonate-http.
package fetch

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/North-web-dev/fpkit/data"
	impersonate "github.com/North-web-dev/impersonate-http"
)

// GetOptions configures a single impersonating request.
type GetOptions struct {
	URL     string
	Profile string
	Method  string
	Headers []string // "Name: Value"
	Body    string
	Out     string // file path, or "" for stdout
	Timeout time.Duration
	Stdout  io.Writer
	Stderr  io.Writer
}

// Get performs a browser-impersonating request and writes the body out.
func Get(o GetOptions) error {
	if o.Stdout == nil {
		o.Stdout = os.Stdout
	}
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
	client, ok := impersonate.NewByName(o.Profile, impersonate.WithTimeout(o.Timeout))
	if !ok {
		return fmt.Errorf("unknown profile %q (have: %s)", o.Profile, strings.Join(profileNames(), ", "))
	}
	method := o.Method
	if method == "" {
		if o.Body != "" {
			method = http.MethodPost
		} else {
			method = http.MethodGet
		}
	}
	var body io.Reader
	if o.Body != "" {
		body = strings.NewReader(o.Body)
	}
	req, err := http.NewRequest(method, o.URL, body)
	if err != nil {
		return err
	}
	for _, h := range o.Headers {
		k, v, found := strings.Cut(h, ":")
		if !found {
			return fmt.Errorf("bad header %q, want 'Name: Value'", h)
		}
		req.Header.Set(strings.TrimSpace(k), strings.TrimSpace(v))
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	fmt.Fprintf(o.Stderr, "%s %s\n", resp.Proto, resp.Status)
	out := o.Stdout
	if o.Out != "" {
		f, err := os.Create(o.Out)
		if err != nil {
			return err
		}
		defer f.Close()
		out = f
	}
	_, err = io.Copy(out, resp.Body)
	return err
}

// CheckOptions configures a drift check.
type CheckOptions struct {
	Reflector string // URL of a /api/all reflector endpoint
	Profile   string
	Fields    []string // subset of ja4, ja4h, akamai
	Timeout   time.Duration
}

// FieldResult is the comparison for one fingerprint field.
type FieldResult struct {
	Field    string
	Expected string
	Measured string
	Match    bool
}

// CheckResult is the outcome of a drift check.
type CheckResult struct {
	Profile  string
	Fields   []FieldResult
	Mismatch bool
}

// Reflected is the subset of a reflector's /api/all response that check uses.
type Reflected struct {
	JA4      string `json:"ja4"`
	JA4H     string `json:"ja4h"`
	AkamaiH2 string `json:"akamai_h2"`
}

// Compare checks a reflected fingerprint against a dataset entry's expected
// values for the named fields.
func Compare(entry data.Entry, ref Reflected, fields []string) (*CheckResult, error) {
	if len(fields) == 0 {
		fields = []string{"ja4"}
	}
	res := &CheckResult{Profile: entry.Name}
	for _, f := range fields {
		var exp, meas string
		switch f {
		case "ja4":
			exp, meas = entry.TLS.JA4, ref.JA4
		case "ja4h":
			exp, meas = entry.JA4H, ref.JA4H
		case "akamai", "akamai_h2":
			exp, meas = entry.HTTP2.AkamaiFingerprint, ref.AkamaiH2
		default:
			return nil, fmt.Errorf("unknown field %q (ja4|ja4h|akamai)", f)
		}
		match := exp != "" && exp == meas
		if !match {
			res.Mismatch = true
		}
		res.Fields = append(res.Fields, FieldResult{Field: f, Expected: exp, Measured: meas, Match: match})
	}
	return res, nil
}

// Check fetches the reflector with the impersonating client and compares the
// reflected fingerprint to the profile's expected values in the dataset.
func Check(o CheckOptions) (*CheckResult, error) {
	db, err := data.Load()
	if err != nil {
		return nil, err
	}
	entry, ok := db.Get(o.Profile)
	if !ok {
		return nil, fmt.Errorf("no dataset entry for profile %q", o.Profile)
	}
	client, ok := impersonate.NewByName(o.Profile, impersonate.WithTimeout(o.Timeout))
	if !ok {
		return nil, fmt.Errorf("unknown impersonation profile %q", o.Profile)
	}
	resp, err := client.Get(o.Reflector)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var ref Reflected
	if err := json.Unmarshal(raw, &ref); err != nil {
		return nil, fmt.Errorf("reflector did not return JSON (%s): %w", o.Reflector, err)
	}
	return Compare(entry, ref, o.Fields)
}

func profileNames() []string {
	out := make([]string, 0, len(impersonate.Profiles))
	for k := range impersonate.Profiles {
		out = append(out, k)
	}
	return out
}
