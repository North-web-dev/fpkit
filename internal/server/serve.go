package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	guard "github.com/North-web-dev/ja4-guard/guard"
	"golang.org/x/net/http2"
)

// serveTLS fingerprints every inbound TLS client and serves h, driving HTTP/2
// and HTTP/1.1 per connection. The stdlib server only dispatches h2 for a
// concrete *tls.Conn, which our capture wrapper is not, so each connection is
// served directly. certFile/keyFile may be empty for a self-signed cert.
func serveTLS(name, addr, certFile, keyFile string, h http.Handler) error {
	cfg, ss, err := tlsConfig(certFile, keyFile)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if ss {
		fmt.Fprintf(os.Stderr, "fp %s: using a self-signed certificate (clients will warn; JA4 is still captured).\n", name)
	}
	fmt.Fprintf(os.Stderr, "fp %s: listening on https://%s\n", name, ln.Addr())
	cln := &captureListener{guard.NewListener(ln, cfg)}
	h2s := &http2.Server{}
	for {
		c, aerr := cln.Accept()
		if aerr != nil {
			return aerr
		}
		go serveConn(c, h, h2s)
	}
}

func serveConn(c net.Conn, h http.Handler, h2s *http2.Server) {
	defer c.Close()
	tc := underlyingTLS(c)
	if tc != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := tc.HandshakeContext(ctx)
		cancel()
		if err != nil {
			return
		}
		if tc.ConnectionState().NegotiatedProtocol == "h2" {
			base := context.Background()
			if cc := asCaptureConn(c); cc != nil {
				base = context.WithValue(base, ctxKey{}, cc)
			}
			h2s.ServeConn(c, &http2.ServeConnOpts{Handler: h, Context: base})
			return
		}
	}
	serveH1(c, h)
}

func underlyingTLS(c net.Conn) *tls.Conn {
	cc := asCaptureConn(c)
	if cc == nil || cc.Conn == nil {
		return nil
	}
	if tc, ok := cc.Conn.Conn.(*tls.Conn); ok {
		return tc
	}
	return nil
}

var errOneShotDone = errors.New("one-shot listener drained")

// serveH1 serves a single already-handshaken connection over HTTP/1.x using a
// standard http.Server (for ConnContext + timeouts) fed a one-shot listener.
func serveH1(c net.Conn, h http.Handler) {
	done := make(chan struct{})
	nc := &notifyConn{Conn: c, done: done}
	srv := &http.Server{
		Handler:           h,
		ConnContext:       connContext,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	srv.Serve(&oneShotListener{c: nc, done: done})
}

type oneShotListener struct {
	c    net.Conn
	used bool
	done chan struct{}
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	if !l.used {
		l.used = true
		return l.c, nil
	}
	<-l.done
	return nil, errOneShotDone
}
func (l *oneShotListener) Close() error   { return nil }
func (l *oneShotListener) Addr() net.Addr { return l.c.LocalAddr() }

type notifyConn struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (n *notifyConn) Close() error {
	n.once.Do(func() { close(n.done) })
	return n.Conn.Close()
}
