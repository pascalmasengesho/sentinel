# User guide

## Authorization and scope

Only run Sentinel against assets you are explicitly permitted to assess. Pass `--authorized` only after confirming the bug-bounty program or engagement permits the chosen hostname, ports, techniques, and request volume. Sentinel's safeguards supplement—not replace—those rules.

The selected hostname is the HTTP scope. Redirects, JavaScript, sitemap documents, and wordlist paths that leave that host are blocked. Private or reserved address targets require `--allow-private`, intended only for your own lab.

For a program with more than one authorized target, use a local YAML scope manifest. It is an
enforcement layer, not proof of authorization: `--authorized` remains mandatory. Host patterns may
be exact (`example.com`) or subdomain-only (`*.example.com`); paths and hosts explicitly excluded
by the manifest are blocked before an HTTP request is sent. See
[`examples/authorized-scope.yaml`](../examples/authorized-scope.yaml).

```bash
sentinel scan https://app.example.com --authorized --scope program-scope.yaml
sentinel batch program-scope.yaml --authorized --format html --output-dir reports/program
```

`batch` scans only the manifest's explicit `targets` and runs them sequentially. Its effective rate
cannot exceed `rate_limit_per_second` in the manifest.

Use `monitor` for quick asynchronous change tracking of the same explicit target list:

```bash
sentinel monitor program-scope.yaml --authorized --state .sentinel/assets.db \
  --concurrency 4 --rate 0.5
```

It uses a shared semaphore and rate limiter, handles DNS/connect/timeout failures per target, and
does not abort the rest of the monitor run when one target fails. It stores only local, header-derived
status, `Content-Length` (when supplied), and a small technology summary. The first run reports all
assets as new; later output is a Markdown table containing only new assets, status changes, or known
content-length changes. Missing `Content-Length` is treated as unknown and never creates a size delta.

## Standard scan

```bash
sentinel scan https://app.example.com --authorized --format markdown --output reports/app
```

The scan performs DNS (including published SPF/DMARC email-policy records), a root HTTP request and an OPTIONS request, normal TLS metadata collection for HTTPS, a small TCP-connect scan, robots/sitemap parsing, root-page technology/header inspection, and same-host scripts. Default request starts are limited to one per second.

The HTTP analysis also records cookie names and non-sensitive attributes, then flags missing
`Secure`, session-like `HttpOnly`, and explicit `SameSite` controls where appropriate. It inspects
the `Allow` response header without sending state-changing methods, and reviews observed CSP/HSTS
policy quality. Cookie values are redacted and never saved in report evidence.

Sentinel also maps public form actions, password-form metadata, authentication links, GraphQL
references, and WebSocket URLs from the root page. It does not submit a form, authenticate, open a
WebSocket, or probe a GraphQL candidate. A password form using `GET`, a password form posting to
HTTP, or a cross-origin form action is reported as an observation for manual, in-scope review.

JavaScript triage focuses on application structure rather than generic token hunting. It downloads
only same-host scripts found on the root page and, when `--crawl` is enabled, bounded crawled pages.
It skips recognizable jQuery, Bootstrap, React DOM, and similar vendor framework files, then records
the script URL alongside application-route candidates, a small set of query flags (such as `debug`
and `test_env`), S3 bucket references, and custom internal-style `X-` header names. Database URI
patterns are reported only as a redacted marker and offset; Sentinel never outputs connection-string
or API-token values, accesses buckets, or sends the identified headers.

## Optional features

`--passive-subdomains` queries crt.sh. This is passive with respect to the target but shares the domain name with that public service.

`--whois` queries public WHOIS servers for a small, report-safe subset of registration metadata (registrar, dates, name servers). It is opt-in; no WHOIS traffic is sent by default.

`--takeover-check` (requires `--passive-subdomains`) performs DNS-only triage of every CT-discovered subdomain. It flags NXDOMAIN names, CNAME records whose target no longer resolves, and CNAMEs pointing at common third-party service providers without an A record. Sentinel never connects to or claims those services; candidates are manual-review leads only.

`--email-security` is enabled by default and reads only published SPF and DMARC DNS records. It never sends email. Use `--no-email-security` to disable it.

`--api-probe` checks only `/openapi.json`, `/swagger.json`, `/api-docs`, and `/graphql`; it makes GET requests and reports 200, 401, and 403 responses. Enable it only if those requests are in scope.

`--public-artifacts` reads only `/favicon.ico`, `/.well-known/security.txt`, and `/security.txt` on the selected host. It records a SHA-256 favicon fingerprint and published security contact metadata; it does not follow contacts, submit forms, or request discovered paths.

`--content-discovery --wordlist PATH` requests up to `max_directory_requests` paths from your controlled wordlist. Keep it slow and use only paths and rate limits permitted by the program.

`--crawl` enables a small HTML link crawler. It begins with the already-collected root page, follows
only same-host `a`/`area` HTTP(S) links with no query string, uses GET only, respects configured
page/depth limits, and conservatively skips paths listed as `Disallow` in the fetched `robots.txt`.
It never submits forms, visits cross-origin links, executes JavaScript, or requests assets such as
images and stylesheets.

`--banners` reads up to 256 bytes after an open TCP connection only when a service sends a banner first. It never sends an application payload.

## Configuration

Copy `sentinel.example.yaml`, edit it, and select a profile:

```bash
sentinel scan example.com --authorized --config sentinel.yaml --profile passive
```

CLI flags override settings in the file. `sentinel config` prints default values.

## Interpreting results

Use reports as a research notebook. Missing headers can be intentional, WAF/CDN detection is heuristic, and a JavaScript structural reference is not proof that the route, bucket, header, or connection is active or in scope. The report does not assign CVSS; score only a verified, scoped finding after you understand impact.

## Enterprise HTML reports

HTML reports preserve the same scan data as JSON while adding an executive summary, transparent risk calculation, severity charts, searchable and sortable findings, structured module summaries, dark/light themes, print styling, and an Investigation Assistant. The Investigation Assistant never claims exploitation: it records why an observation might matter, what evidence is missing, and safe manual validation steps.

Use `--brand-name` and `--logo-url` with `--format html` to customize the presentation. The logo URL is embedded in the report only; Sentinel does not fetch it during scanning.

## Local research workspace

Pass `--workspace PATH` to retain a completed scan in a local SQLite file. This is opt-in and
does not create any additional requests or transmit stored reports. It stores the completed scan
snapshot and its effective configuration so future investigation can be reproducible.

```bash
sentinel scan https://app.example.com --authorized --workspace .sentinel/app.db
sentinel workspace history .sentinel/app.db --target https://app.example.com/
sentinel workspace compare .sentinel/app.db 1 2 --output reports/app-changes.json
sentinel workspace graph .sentinel/app.db 2 --output reports/app-graph.json
```

`workspace compare` reports new and no-longer-observed scan records plus changed module data. It
does not say that a change is a vulnerability. `workspace graph` produces stable JSON nodes and
relationships for a future interactive graph viewer; it derives domains, DNS, passive subdomains,
technologies, certificates, cookies, ports, JavaScript, APIs, published URLs, artifacts, and
observations only from the saved report.

Add and search manual notes locally:

```bash
sentinel workspace note .sentinel/app.db --target https://app.example.com/ \
  --text "Confirm API behavior safely" --tags api,follow-up --favorite
sentinel workspace notes .sentinel/app.db follow-up
```
