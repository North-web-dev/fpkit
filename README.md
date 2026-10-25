# fpkit — `fp`

**One binary for both sides of the TLS/HTTP fingerprinting wire.** `fp` lets you
*read* a client's fingerprint (JA3/JA4/JA4H/Akamai-H2), *forge* one byte-exact
(the "unblockable curl"), *guard* a service by who's really knocking, *capture*
arbitrary webhooks with the caller's JA4 attached, and *reverse-look-up* any JA4
against a bundled dataset of real browsers and known automation clients. The
fingerprint data ships *in the same repo* — measured, not guessed.

```
┌─ read ──────────────┐        ┌─ write ─────────────┐
│ fp inspect   (you)  │        │ fp get      (fetch) │
│ fp hook   (webhook) │  <==>  │ fp check    (CI)    │
│ fp guard  (proxy)   │        │ fp db   (lookup)    │
└─────────────────────┘        └─────────────────────┘
```

Built as thin orchestration over three focused libraries:
[`ja4plus-go`](https://github.com/North-web-dev/ja4plus-go) (compute JA4+),
[`impersonate-http`](https://github.com/North-web-dev/impersonate-http)
(byte-exact browser TLS+H2), and
[`ja4-guard`](https://github.com/North-web-dev/ja4-guard) (inbound ClientHello
capture).

## Install

```sh
go install github.com/North-web-dev/fpkit/cmd/fp@latest
```

Or Docker (distroless, multi-arch):

```sh
docker run --rm -p 8443:8443 ghcr.io/north-web-dev/fpkit:latest inspect --addr :8443
```

Prebuilt binaries for linux/darwin · amd64/arm64 are attached to each
[release](https://github.com/North-web-dev/fpkit/releases).

## Commands

### `fp db` — reverse-look-up a JA4

Query the embedded dataset. `ja4` answers "what is this?" — a browser, a known
automation client/library, or unknown.

```console
$ fp db ja4 t13d3113h2_e8f1e7e78f70_ce5650b735ce
t13d3113h2_e8f1e7e78f70_ce5650b735ce
  curl (HTTP/2 ALPN) 7.81.0 — NOT a browser ❌
  · curl-http2         tool         curl (HTTP/2 ALPN) 7.81.0 (measured 2026-10-25 via https://fp.shshbshsnang.shop/api/all)

$ fp db ja4 t13d1516h2_8daaf6152771_d8a2da3f94cd
t13d1516h2_8daaf6152771_d8a2da3f94cd
  Google Chrome 131 (Windows) — browser ✅
  · chrome             browser      Google Chrome 131 (Windows) (measured 2026-07-03 via tls.peet.ws)
```

When several clients legitimately share a JA4, the lookup returns all of them
rather than guessing:

```console
$ fp db ja4 t13d1812h1_85036bcba153_d41ae481755e
t13d1812h1_85036bcba153_d41ae481755e
  python-aiohttp 3.13.5 / python-httpx 0.28.1 — NOT a browser ❌
  · python-aiohttp     library      python-aiohttp 3.13.5 (measured 2026-10-25 via https://fp.shshbshsnang.shop/api/all)
  · python-httpx       library      python-httpx 0.28.1 (measured 2026-10-25 via https://fp.shshbshsnang.shop/api/all)
```

`fp db list` prints the whole table; `fp db show <name>` prints one entry as JSON.

### `fp inspect` — reflector / self-inspector

A server that tells any client what *it* looks like, via an embedded web UI and
`GET /api/all`. The top of the UI shows a shareable verdict ("You look like:
… — browser ✅ / not a browser ❌"), derived from the same reverse lookup, above
the raw JA4/JA3/Akamai.

```console
$ fp inspect --addr :8443
fp inspect: using a self-signed certificate (clients will warn; JA4 is still captured).
fp inspect: listening on https://[::]:8443
```

Hitting it with curl (which reads as a non-browser):

```console
$ curl -sk --http2 https://localhost:8443/api/all | jq '{ja4, ja4h, akamai_h2, verdict: .verdict.summary}'
{
  "ja4": "t13d3113h2_e8f1e7e78f70_ce5650b735ce",
  "ja4h": "ge20nn020000_5594a17e7e7e_000000000000_000000000000",
  "akamai_h2": "3:100;4:33554432;2:0|33488897|0|m,p,s,a",
  "verdict": "You look like: curl (HTTP/2 ALPN) 7.81.0 — not a browser"
}
```

**To fingerprint TLS, `fp inspect` terminates TLS itself** — it is not a
TLS-terminating *proxy*. If you put it behind nginx, use SNI passthrough
(`ssl_preread`), not a terminating `proxy_pass`, or it will measure the proxy
instead of the client. Pass `--tls-cert`/`--tls-key` for a real certificate;
otherwise a self-signed one is generated in memory.

### `fp get` — the unblockable curl

Fetch a URL impersonating a real browser, byte-exact at the TLS and HTTP/2
layers (via `impersonate-http`'s uTLS templates), so it survives JA3/JA4
blocking without a headless browser.

```console
$ fp get https://fp.shshbshsnang.shop/api/all --profile chrome | jq .ja4
HTTP/2.0 200 OK
"t13d1516h2_8daaf6152771_d8a2da3f94cd"
```

That JA4 is exactly the dataset's Chrome JA4 — the handshake reads as Chrome, as
measured by an independent reflector. Flags: `--profile`
(chrome/firefox/safari/edge/ios/chrome_android), `-X` method, `-H 'Name:
Value'` (repeatable), `-d` body, `-o` file.

### `fp check` — CI drift detection

Verify the chosen client still reads as the target browser; exits non-zero on
drift with `--fail-on-mismatch`. It fetches a reflector with the impersonating
client and compares the reflected fingerprint to the dataset's expected values.

```console
$ fp check --reflector --profile chrome --fields ja4,akamai
profile=chrome reflector=https://fp.shshbshsnang.shop/api/all
  [OK  ] ja4     expected=t13d1516h2_8daaf6152771_d8a2da3f94cd measured=t13d1516h2_8daaf6152771_d8a2da3f94cd
  [OK  ] akamai  expected=1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p measured=1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
result: MATCH — client reads as the target browser
```

### `fp guard` — fingerprint inbound clients at the edge

A reverse proxy that computes each client's JA4 and applies a policy before
forwarding. `known-browser` only lets through JA4s that reverse-look-up to a
browser in the dataset; `deny-list` blocks known automation clients; `allow`
fingerprints and logs without blocking.

```console
$ fp guard --upstream http://127.0.0.1:8080 --policy known-browser --addr :8443
fp guard: policy=known-browser upstream=http://127.0.0.1:8080
fp guard: listening on https://[::]:8443
fp guard: GET / ja4=t13d3113h2_e8f1e7e78f70_ce5650b735ce (curl (HTTP/2 ALPN) 7.81.0) -> DENY [default-deny]
```

A curl request to that proxy receives `403`.

### `fp hook` — webhook / request inspector with JA4

`POST /api/bins` creates a bin; any request to `/b/{id}/...` is captured
(method, URL, headers, body — size-capped with truncation noted) and viewable
live at `/i/{id}`. Unique to `fp hook`: each captured request also shows the
**caller's JA4** when it arrived over TLS, `n/a` on plain HTTP (never faked).

```console
$ curl -sk -X POST https://localhost:8443/api/bins
{"id":"e3b8f8cf503a76b8a1"}

$ curl -sk --http2 -X POST 'https://localhost:8443/b/e3b8f8cf503a76b8a1/webhook' \
    -H 'Content-Type: application/json' -d '{"msg":"<script>alert(1)</script>"}'

$ curl -sk https://localhost:8443/api/bins/e3b8f8cf503a76b8a1/requests \
    | jq '.requests[0] | {method, ja4, verdict: .ja4_verdict.summary, body}'
{
  "method": "POST",
  "ja4": "t13d3113h2_e8f1e7e78f70_ce5650b735ce",
  "verdict": "You look like: curl (HTTP/2 ALPN) 7.81.0 — not a browser",
  "body": "{\"msg\":\"<script>alert(1)</script>\"}"
}
```

Bins live in memory with a TTL (`--ttl`, default 2h), a per-bin ring buffer
(100 requests), and a global cap. Bin IDs are unguessable (crypto/rand).

## Embedded data

The dataset lives at [`data/fingerprints.json`](data/fingerprints.json),
embedded with `go:embed`, with its schema and provenance documented in
[`data/SCHEMA.md`](data/SCHEMA.md). It merges:

- **browser + live-engine fingerprints** from
  [`North-web-dev/fingerprint-db`](https://github.com/North-web-dev/fingerprint-db)
  (curated browsers measured via uTLS `*_Auto` templates against `tls.peet.ws`,
  plus live Playwright Chromium/Firefox/WebKit engines), and
- **measured non-browser client fingerprints** (curl, wget, Go, Java, Node,
  Python) captured against `fp.shshbshsnang.shop`.

Current contents: **19 entries — 5 browsers, 3 engines, 11 known clients.** Every
entry carries per-entry provenance (`source`, `method`, `measured`). `fingerprint-db`
is the upstream of record for browser data.

## Does / does not

**Does**
- Compute JA4 / JA4_r / JA4H / Akamai-H2 for inbound clients over TLS.
- Forge byte-exact Chrome/Firefox/Safari/Edge/iOS TLS + HTTP/2 handshakes.
- Reverse-look-up a JA4 to a browser, a known tool/library, or "unknown".
- Enforce allow / known-browser / deny-list policy at a reverse proxy.
- Capture webhooks with the caller's JA4, serving an XSS-safe live UI.

**Does not**
- Compute a *live* JA3 in `fp inspect` — JA4/JA4_r supersede it, and the
  dataset carries JA3 for known browsers; live JA3 is not reconstructed.
- Carry a `ja4h` for the curated browser entries (only live-engine and client
  entries have one measured), so `fp check --fields ja4h` against a curated
  browser reports drift honestly.
- Prevent a determined spoofer — JA4 is derived from fields the client controls
  (see threat model).
- Persist hook captures — they are in-memory only.

## Roadmap

- Weekly data-refresh workflow that re-measures the live section and opens a PR.
- `fp hook` forwarding/replay (forward captured requests to a real upstream).
- More impersonation profiles and an offline `fp check` against a captured
  `/api/all` fixture.

## Security notes

- **`fp hook` is XSS-safe by construction.** Captured content is attacker-
  controlled; the data channel is strict JSON and the UI renders every value
  with `textContent`, never `innerHTML`. The viewer page never inlines captured
  content server-side. Bodies are size-capped and bin IDs are unguessable.
- **`fp guard` threat model.** JA4/JA4H are computed from fields the client
  controls, so a careful adversary can forge any JA4 (indeed, that is exactly
  what `fp get` does). Treat `fp guard` as a cheap, high-signal filter against
  commodity tooling and a strong logging/triage signal — not as authentication.
  Deny decisions are reliable against clients that do not deliberately spoof;
  allow decisions are not proof of a real browser.
- Self-signed certificates are only a convenience for local use; supply real
  certs in production.

## Development

```sh
make check   # gofmt + go vet + go test -race (incl. dataset validation)
make build   # -> ./fp
```

`go build ./... && go vet ./... && gofmt -l . && go test ./... -race` is green.

## License

MIT — see [LICENSE](LICENSE). JA4+ is the work of FoxIO, LLC; the JA4 method is
BSD-3-Clause and the remaining JA4+ methods are governed by the FoxIO License
1.1. This project implements orchestration only and relies on `ja4plus-go` for
the fingerprint algorithms.

## Support

If fpkit saves you an afternoon of fighting anti-bot walls, a ⭐ or a tip keeps the
measurements fresh.

| Coin | Address |
|---|---|
| **BTC** | `bc1q0sfghv7yfl594gjurhyhlhdgm0dtwh4dkjha36` |
| **ETH / USDT-ERC20 / BNB-BEP20** | `0xB827b5a8B6c5111946c5D872933b2C23484E87dE` |
| **SOL** | `3ch5aHrPp3CierhiNXmqmtFH2dMHh6Gfv7a97KtLMMCh` |
| **USDT-TRC20 / TRX** | `TUAyz7TjgJdFVD2oFHWUUTNrzzAnBRgySG` |
| **TON** | `UQAJmYVuR3hh02etjaPKJF-h6jcpdSnq9ZIFvI64NEskS6tx` |
