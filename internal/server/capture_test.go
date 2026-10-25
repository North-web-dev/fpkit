package server

import (
	"bytes"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// buildH2 produces a client preface + SETTINGS + WINDOW_UPDATE + HEADERS stream
// so parseH2 can be tested without a live browser.
func buildH2(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString(h2Preface)
	fr := http2.NewFramer(&buf, nil)
	if err := fr.WriteSettings(
		http2.Setting{ID: http2.SettingHeaderTableSize, Val: 65536},
		http2.Setting{ID: http2.SettingEnablePush, Val: 0},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 6291456},
		http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: 262144},
	); err != nil {
		t.Fatal(err)
	}
	if err := fr.WriteWindowUpdate(0, 15663105); err != nil {
		t.Fatal(err)
	}
	var hbuf bytes.Buffer
	enc := hpack.NewEncoder(&hbuf)
	for _, kv := range [][2]string{
		{":method", "GET"}, {":authority", "example.com"}, {":scheme", "https"}, {":path", "/"},
		{"user-agent", "test"}, {"accept", "*/*"},
	} {
		enc.WriteField(hpack.HeaderField{Name: kv[0], Value: kv[1]})
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: 1, BlockFragment: hbuf.Bytes(), EndHeaders: true, EndStream: true,
	}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestParseH2Akamai(t *testing.T) {
	stream := buildH2(t)
	ak, meth, hdrs, ok := parseH2(stream[len(h2Preface):])
	if !ok {
		t.Fatal("parseH2 reported failure")
	}
	want := "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
	if ak != want {
		t.Errorf("akamai = %q, want %q", ak, want)
	}
	if meth != "GET" {
		t.Errorf("method = %q, want GET", meth)
	}
	if len(hdrs) != 2 || hdrs[0].Name != "user-agent" {
		t.Errorf("unexpected regular headers: %+v", hdrs)
	}
}

func TestParseH2RejectsNonPreface(t *testing.T) {
	cc := &captureConn{}
	cc.buf.WriteString("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	cc.parse()
	if cc.isHTTP2 {
		t.Error("HTTP/1.x bytes should not be detected as HTTP/2")
	}
	if cc.Akamai() != "" {
		t.Error("no akamai fingerprint expected for HTTP/1.x")
	}
}

func TestParseH1Head(t *testing.T) {
	req, ok := parseH1Head([]byte("GET /x HTTP/1.1\r\nHost: a\r\nAccept: */*\r\n\r\n"))
	if !ok {
		t.Fatal("parseH1Head failed")
	}
	if req.Method != "GET" || len(req.Headers) != 2 {
		t.Errorf("unexpected parse: %+v", req)
	}
}
