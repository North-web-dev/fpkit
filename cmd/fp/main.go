// Command fp is one binary for both sides of TLS/HTTP fingerprinting:
// inspect inbound clients, impersonate browsers, guard a service, capture
// webhooks, and reverse-look-up JA4 against a bundled dataset.
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/North-web-dev/fpkit/internal/fetch"
	"github.com/North-web-dev/fpkit/internal/server"
)

const usage = `fp — TLS/HTTP fingerprinting, both sides of the wire.

Usage:
  fp inspect [--addr :8443] [--tls-cert FILE --tls-key FILE]
        Reflector: a client hitting it sees its own JA4/JA4H/Akamai-H2.
  fp get <url> [--profile chrome|firefox|safari|edge|ios|chrome_android]
        [-X METHOD] [-H 'Name: Value' ...] [-d BODY] [-o FILE]
        Fetch a URL impersonating a real browser (byte-exact TLS + HTTP/2).
  fp check <url> | --reflector [--profile chrome] [--fields ja4,ja4h,akamai]
        [--fail-on-mismatch]
        CI mode: verify the chosen client still reads as the target browser.
  fp guard --upstream <url> [--addr :8443] [--policy allow|known-browser|deny-list]
        Reverse proxy that fingerprints inbound clients and applies a policy.
  fp hook [--addr :8443] [--no-tls] [--ttl 2h]
        Webhook/request inspector with the caller's JA4 per request.
  fp db list | show <name> | ja4 <value>
        Query the embedded dataset; ja4 is a reverse lookup.

Run 'fp <command> -h' for command flags.
`

const defaultReflector = "https://fp.shshbshsnang.shop/api/all"

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	var err error
	switch cmd {
	case "inspect":
		err = cmdInspect(args)
	case "get":
		err = cmdGet(args)
	case "check":
		err = cmdCheck(args)
	case "guard":
		err = cmdGuard(args)
	case "hook":
		err = cmdHook(args)
	case "db":
		err = cmdDB(args)
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, usage)
		return
	case "version", "-v", "--version":
		fmt.Printf("fp %s\n", version)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "fp %s: %v\n", cmd, err)
		os.Exit(1)
	}
}

func cmdInspect(args []string) error {
	fs := newFlagSet("inspect")
	addr := fs.String("addr", ":8443", "listen address")
	cert := fs.String("tls-cert", "", "TLS certificate file (self-signed if empty)")
	key := fs.String("tls-key", "", "TLS key file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return server.RunInspect(server.InspectConfig{Addr: *addr, TLSCert: *cert, TLSKey: *key})
}

func cmdGuard(args []string) error {
	fs := newFlagSet("guard")
	addr := fs.String("addr", ":8443", "listen address")
	upstream := fs.String("upstream", "", "upstream URL to proxy to (required)")
	policy := fs.String("policy", "allow", "allow | known-browser | deny-list")
	cert := fs.String("tls-cert", "", "TLS certificate file (self-signed if empty)")
	key := fs.String("tls-key", "", "TLS key file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *upstream == "" {
		return fmt.Errorf("--upstream is required")
	}
	return server.RunGuard(server.GuardConfig{Addr: *addr, Upstream: *upstream, Policy: *policy, TLSCert: *cert, TLSKey: *key})
}

func cmdHook(args []string) error {
	fs := newFlagSet("hook")
	addr := fs.String("addr", ":8443", "listen address")
	cert := fs.String("tls-cert", "", "TLS certificate file (self-signed if empty)")
	key := fs.String("tls-key", "", "TLS key file")
	noTLS := fs.Bool("no-tls", false, "serve plain HTTP (JA4 reported as n/a)")
	ttl := fs.Duration("ttl", 2*time.Hour, "how long bins live")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return server.RunHook(server.HookConfig{Addr: *addr, TLSCert: *cert, TLSKey: *key, NoTLS: *noTLS, TTL: *ttl})
}

func cmdGet(args []string) error {
	fs := newFlagSet("get")
	profile := fs.String("profile", "chrome", "browser profile to impersonate")
	method := fs.String("X", "", "HTTP method")
	body := fs.String("d", "", "request body")
	out := fs.String("o", "", "write body to file instead of stdout")
	timeout := fs.Duration("timeout", 30*time.Second, "request timeout")
	var headers multiFlag
	fs.Var(&headers, "H", "request header 'Name: Value' (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: fp get <url> [flags]")
	}
	return fetch.Get(fetch.GetOptions{
		URL: fs.Arg(0), Profile: *profile, Method: *method,
		Headers: headers, Body: *body, Out: *out, Timeout: *timeout,
	})
}

func cmdCheck(args []string) error {
	fs := newFlagSet("check")
	profile := fs.String("profile", "chrome", "browser profile to verify")
	useReflector := fs.Bool("reflector", false, "use the built-in default reflector")
	fieldsCSV := fs.String("fields", "ja4", "comma-separated: ja4,ja4h,akamai")
	failOn := fs.Bool("fail-on-mismatch", false, "exit non-zero on any mismatch")
	timeout := fs.Duration("timeout", 30*time.Second, "request timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	reflector := defaultReflector
	if fs.NArg() >= 1 {
		reflector = fs.Arg(0)
	} else if !*useReflector {
		return fmt.Errorf("usage: fp check <url> | --reflector")
	}
	res, err := fetch.Check(fetch.CheckOptions{
		Reflector: reflector, Profile: *profile,
		Fields: splitCSV(*fieldsCSV), Timeout: *timeout,
	})
	if err != nil {
		return err
	}
	printCheck(res, reflector)
	if res.Mismatch && *failOn {
		os.Exit(1)
	}
	return nil
}
