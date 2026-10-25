# Dataset schema & provenance

`fingerprints.json` is the single embedded dataset that powers `fp db`,
`fp check`, and `fp guard`'s known-browser / deny-list policies. Every value is
**measured, not guessed**, and carries its own provenance.

## Top level

| Field | Meaning |
|---|---|
| `schema_version` | Dataset schema version (`"1"`). |
| `generated` | ISO date the merged file was assembled. |
| `note` | Human summary. |
| `sources` | Upstream sources, each `{name, url, role}`. |
| `entries` | The fingerprint records (array). |

## Entry

| Field | Meaning |
|---|---|
| `name` | Unique key used by `fp db show <name>`. |
| `kind` | `browser`, `engine`, or `client`. |
| `category` | `browser`, `browser-engine`, `tool`, or `library`. |
| `verdict` | `browser`, `browser-engine`, or `non-browser` — what a JA4 match means. |
| `label` | Human-readable name shown by the reverse lookup and UIs. |
| `user_agent` | UA string, where known. |
| `utls_client_hello_id` | uTLS template used to measure a curated browser (browsers only). |
| `tls` | `{ja3, ja3_hash, ja4}`. `ja4` is always present; `ja3` may be empty for client entries measured JA4-only. |
| `http2` | `{akamai_fingerprint, akamai_hash}` — the HTTP/2 framing fingerprint, where measured. |
| `ja4h` | JA4H HTTP fingerprint, where measured. |
| `provenance` | `{source, method, measured}` — how and when this entry was captured. |

## Sources

- **North-web-dev/fingerprint-db** — curated browser fingerprints measured via
  uTLS `*_Auto` templates against `tls.peet.ws`, plus a `live` section of
  real-engine fingerprints (Playwright Chromium/Firefox/WebKit + a curl
  baseline) measured against `fp.shshbshsnang.shop`. This is the upstream of
  record for browser data.
- **work-threatfeed/measure** — non-browser client fingerprints (curl, wget,
  Go `net/http`, Java `HttpClient`, Node undici, Python urllib/aiohttp/httpx/
  requests) measured against `fp.shshbshsnang.shop`.

## Honest notes

- Some clients legitimately share a JA4 (e.g. `python-aiohttp` and
  `python-httpx` both measure `t13d1812h1_85036bcba153_d41ae481755e`). Reverse
  lookup returns **all** matching entries rather than guessing one.
- JA4 is stable across GREASE but changes with SNI presence (`t13d…` with SNI
  vs `t13i…` to a bare IP), TLS library version, and platform. Treat the set as
  a measured seed, not an exhaustive registry.
- The curated browser entries do not carry a `ja4h`; only the live engine and
  measured client entries do. `fp check --fields ja4h` against a curated
  browser therefore reports drift (expected value is empty) — this is honest,
  not a bug.

## Regenerating

The dataset is assembled from the two sources above. The embedded copy is the
source of truth for the binary; `go test ./data/` validates that it parses and
that reverse lookup works.
