package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	guard "github.com/North-web-dev/ja4-guard/guard"
	ja4plus "github.com/North-web-dev/ja4plus-go"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const captureLimit = 32 << 10

const h2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// captureConn wraps a *guard.Conn and mirrors the first decrypted bytes of the
// client stream so the HTTP/2 Akamai fingerprint, pseudo-header order and h2
// JA4H can be derived. JA4/JA4Raw/ServerName are promoted from guard.Conn.
type captureConn struct {
	*guard.Conn
	mu      sync.Mutex
	buf     bytes.Buffer
	done    bool
	akamai  string
	h2meth  string
	h2hdrs  []ja4plus.Header
	isHTTP2 bool
}

func (c *captureConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		if room := captureLimit - c.buf.Len(); room > 0 {
			if n <= room {
				c.buf.Write(p[:n])
			} else {
				c.buf.Write(p[:room])
			}
		}
		c.mu.Unlock()
	}
	return n, err
}

func (c *captureConn) parse() {
	if c.done {
		return
	}
	data := c.buf.Bytes()
	if len(data) < len(h2Preface) || string(data[:len(h2Preface)]) != h2Preface {
		return
	}
	c.isHTTP2 = true
	ak, meth, hdrs, ok := parseH2(data[len(h2Preface):])
	if ok {
		c.akamai = ak
		c.h2meth = meth
		c.h2hdrs = hdrs
		c.done = true
	}
}

// Akamai returns the client's HTTP/2 Akamai fingerprint, or "" if unavailable.
func (c *captureConn) Akamai() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.parse()
	return c.akamai
}

// JA4H computes the client's JA4H for r, preferring ordered HTTP/2 headers and
// falling back to the raw HTTP/1.x request head captured by guard.
func (c *captureConn) JA4H(r *http.Request) string {
	c.mu.Lock()
	c.parse()
	meth, hdrs, h2 := c.h2meth, c.h2hdrs, c.isHTTP2
	c.mu.Unlock()
	if h2 && meth != "" {
		return ja4plus.JA4H(&ja4plus.HTTPRequest{Method: meth, HTTP2: true, Headers: hdrs})
	}
	if head := c.Conn.RequestHead(); len(head) > 0 {
		if req, ok := parseH1Head(head); ok {
			return ja4plus.JA4H(req)
		}
	}
	return ""
}

func parseH2(data []byte) (akamai, method string, headers []ja4plus.Header, ok bool) {
	fr := http2.NewFramer(io.Discard, bytes.NewReader(data))
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	fr.MaxHeaderListSize = 1 << 20
	var settings []string
	var haveSettings, haveHeaders bool
	window := "0"
	var priorities, pseudo []string
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			break
		}
		switch fv := f.(type) {
		case *http2.SettingsFrame:
			if !fv.IsAck() && !haveSettings {
				fv.ForeachSetting(func(s http2.Setting) error {
					settings = append(settings, fmt.Sprintf("%d:%d", uint16(s.ID), s.Val))
					return nil
				})
				haveSettings = true
			}
		case *http2.WindowUpdateFrame:
			if fv.StreamID == 0 && window == "0" {
				window = strconv.FormatUint(uint64(fv.Increment), 10)
			}
		case *http2.PriorityFrame:
			p := fv.PriorityParam
			ex := 0
			if p.Exclusive {
				ex = 1
			}
			priorities = append(priorities, fmt.Sprintf("%d:%d:%d:%d", fv.StreamID, ex, p.StreamDep, int(p.Weight)+1))
		case *http2.MetaHeadersFrame:
			for _, hf := range fv.Fields {
				switch hf.Name {
				case ":method":
					method = hf.Value
					pseudo = append(pseudo, "m")
				case ":authority":
					pseudo = append(pseudo, "a")
				case ":scheme":
					pseudo = append(pseudo, "s")
				case ":path":
					pseudo = append(pseudo, "p")
				default:
					if !strings.HasPrefix(hf.Name, ":") {
						headers = append(headers, ja4plus.Header{Name: hf.Name, Value: hf.Value})
					}
				}
			}
			haveHeaders = true
		}
		if haveHeaders {
			break
		}
	}
	if !haveSettings {
		return "", "", nil, false
	}
	prio := "0"
	if len(priorities) > 0 {
		prio = strings.Join(priorities, ",")
	}
	akamai = strings.Join(settings, ";") + "|" + window + "|" + prio + "|" + strings.Join(pseudo, ",")
	return akamai, method, headers, true
}

func parseH1Head(head []byte) (*ja4plus.HTTPRequest, bool) {
	lines := strings.Split(strings.ReplaceAll(string(head), "\r\n", "\n"), "\n")
	if len(lines) == 0 {
		return nil, false
	}
	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) < 3 {
		return nil, false
	}
	req := &ja4plus.HTTPRequest{Method: parts[0], Version: strings.TrimSpace(parts[2])}
	for _, ln := range lines[1:] {
		if ln == "" {
			break
		}
		kv := strings.SplitN(ln, ":", 2)
		if len(kv) != 2 {
			continue
		}
		req.Headers = append(req.Headers, ja4plus.Header{Name: kv[0], Value: strings.TrimSpace(kv[1])})
	}
	return req, true
}

type captureListener struct {
	*guard.Listener
}

func (l *captureListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if gc, ok := c.(*guard.Conn); ok {
		return &captureConn{Conn: gc}, nil
	}
	return c, nil
}

type ctxKey struct{}

func connContext(ctx context.Context, c net.Conn) context.Context {
	if cc := asCaptureConn(c); cc != nil {
		return context.WithValue(ctx, ctxKey{}, cc)
	}
	return ctx
}

func asCaptureConn(c net.Conn) *captureConn {
	switch v := c.(type) {
	case *captureConn:
		return v
	case *notifyConn:
		return asCaptureConn(v.Conn)
	}
	return nil
}

func fromRequest(r *http.Request) (*captureConn, bool) {
	cc, ok := r.Context().Value(ctxKey{}).(*captureConn)
	return cc, ok
}
