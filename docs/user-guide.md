# User guide

## Authorization and scope

Only run Sentinel against assets you are explicitly permitted to assess. Pass `--authorized` only after confirming the bug-bounty program or engagement permits the chosen hostname, ports, techniques, and request volume. Sentinel's safeguards supplement—not replace—those rules.

The selected hostname is the HTTP scope. Redirects, JavaScript, sitemap documents, and wordlist paths that leave that host are blocked. Private or reserved address targets require `--allow-private`, intended only for your own lab.

## Standard scan

```bash
sentinel scan https://app.example.com --authorized --format markdown --output reports/app
```

The scan performs DNS, a root HTTP request and an OPTIONS request, normal TLS metadata collection for HTTPS, a small TCP-connect scan, robots/sitemap parsing, root-page technology/header inspection, and same-host scripts. Default request starts are limited to one per second.

The HTTP analysis also records cookie names and non-sensitive attributes, then flags missing
`Secure`, session-like `HttpOnly`, and explicit `SameSite` controls where appropriate. It inspects
the `Allow` response header without sending state-changing methods, and reviews observed CSP/HSTS
policy quality. Cookie values are redacted and never saved in report evidence.

Sentinel also maps public form actions, password-form metadata, authentication links, GraphQL
references, and WebSocket URLs from the root page. It does not submit a form, authenticate, open a
WebSocket, or probe a GraphQL candidate. A password form using `GET`, a password form posting to
HTTP, or a cross-origin form action is reported as an observation for manual, in-scope review.

## Optional features

`--passive-subdomains` queries crt.sh. This is passive with respect to the target but shares the domain name with that public service.

`--api-probe` checks only `/openapi.json`, `/swagger.json`, `/api-docs`, and `/graphql`; it makes GET requests and reports 200, 401, and 403 responses. Enable it only if those requests are in scope.

`--public-artifacts` reads only `/favicon.ico`, `/.well-known/security.txt`, and `/security.txt` on the selected host. It records a SHA-256 favicon fingerprint and published security contact metadata; it does not follow contacts, submit forms, or request discovered paths.

`--content-discovery --wordlist PATH` requests up to `max_directory_requests` paths from your controlled wordlist. Keep it slow and use only paths and rate limits permitted by the program.

`--banners` reads up to 256 bytes after an open TCP connection only when a service sends a banner first. It never sends an application payload.

## Configuration

Copy `sentinel.example.yaml`, edit it, and select a profile:

```bash
sentinel scan example.com --authorized --config sentinel.yaml --profile passive
```

CLI flags override settings in the file. `sentinel config` prints default values.

## Interpreting results

Use reports as a research notebook. Missing headers can be intentional, WAF/CDN detection is heuristic, and a secret-like JavaScript pattern is redacted because it needs careful manual validation. The report does not assign CVSS; score only a verified, scoped finding after you understand impact.

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
