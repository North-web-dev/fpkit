package server

import (
	"net"
	"net/http"
	"strings"

	"github.com/North-web-dev/fpkit/data"
)

// Fingerprint is the per-request fingerprint the reflector and hook expose.
type Fingerprint struct {
	JA4        string       `json:"ja4"`
	JA4Raw     string       `json:"ja4_raw,omitempty"`
	JA4H       string       `json:"ja4h,omitempty"`
	AkamaiH2   string       `json:"akamai_h2,omitempty"`
	SNI        string       `json:"sni,omitempty"`
	ALPN       string       `json:"alpn,omitempty"`
	HTTPVer    string       `json:"http_version"`
	TLS        bool         `json:"tls"`
	Verdict    data.Verdict `json:"verdict"`
	HeaderKeys []string     `json:"header_order,omitempty"`
}

func gather(db *data.DB, r *http.Request) Fingerprint {
	fp := Fingerprint{HTTPVer: r.Proto}
	cc, ok := fromRequest(r)
	if ok {
		fp.TLS = true
		fp.JA4 = cc.JA4()
		fp.JA4Raw = cc.JA4Raw()
		fp.JA4H = cc.JA4H(r)
		fp.AkamaiH2 = cc.Akamai()
		fp.SNI = cc.ServerName()
		fp.ALPN = cc.NegotiatedProtocol()
	} else {
		fp.JA4 = "n/a"
	}
	fp.Verdict = db.Classify(fp.JA4)
	return fp
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func wantsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "application/json")
}
