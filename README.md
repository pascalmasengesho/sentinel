# Sentinel

Sentinel is a Linux-friendly command-line assistant for **authorized** web security assessments. It combines safe, rate-limited reconnaissance and non-destructive configuration checks into evidence-oriented reports.

It is not an exploitation framework. Sentinel does not authenticate, bypass access controls, evade monitoring, submit forms, mutate data, run denial-of-service techniques, enumerate cipher suites, or try credentials. You must have permission and comply with the program's scope before scanning.

## Features

- Target validation, exact-host HTTP scope control, and private-address protection
- DNS records, wildcard-DNS indication, and resolver-provided DNSSEC AD flag
- Published SPF/DMARC email-policy checks through passive DNS; Sentinel never sends mail
- Optional passive CT subdomain lookup, opt-in public WHOIS metadata, and DNS-only
  subdomain-takeover triage for CT-discovered names
- Bounded TCP-connect scan, with optional banner reads only when a service sends one first
- Root HTTP, security headers, cookies, redirects, cache/compression, and advertised methods
- Cookie-attribute hardening, CSP/HSTS posture, and advertised-method observations from responses
  already collected; cookie values are always omitted from findings and reports
- Normal TLS handshake/certificate metadata; it deliberately does not force legacy protocols or enumerate ciphers
- robots.txt and sitemap parsing without requesting robots-disallowed pages
- High-signal same-origin JavaScript triage for routes, query flags, S3 references, and
  internal-style header names, with script-source provenance and redacted database-URI markers
- Passive mapping of public forms, authentication entry points, GraphQL, and WebSocket candidates;
  Sentinel only observes the root page and never submits forms or opens those connections
- Deterministic research priorities that correlate completed module output into safe manual-review
  queues; they never assert a vulnerability or recommend exploitation
- Passive technology, CMS, framework, CDN, WAF, reverse-proxy, and hosting hints
- Optional, low-rate public API-document, public artifact, and user-wordlist discovery
- Optional bounded same-origin crawler: GET-only, query-free links, explicit page/depth limits,
  and conservative robots.txt Disallow handling
- YAML program scopes that allow-list hosts, exclude paths, cap request rate, and enable safe
  sequential batch scans of explicit targets
- Async, header-only asset monitoring with local SQLite baselines and Markdown delta summaries
- Enterprise HTML reporting with risk overview, charts, searchable findings, investigation guidance,
  dark/light themes, print styling, evidence-copy controls, and branding options
- Optional local SQLite research workspaces with scan history, note search, scan comparison, and
  knowledge-graph JSON export; these features never send stored data elsewhere
- JSON, Markdown, HTML, CSV, and PDF reporting; YAML profiles; trusted local plugins
- Opt-in adapters for locally installed external tools — subfinder, amass, nmap,
  nuclei, and ffuf — invoked with bounded timeouts and parsed into normal reports

## Installation

Python 3.12 or later is required.

For end users, install the published package with `pipx install sentinel-bounty`, Docker, Snap, or the AUR. See [distribution and installation](docs/packaging.md) for platform-specific commands and container volume guidance.

For local development:

```bash
git clone https://github.com/pascalmasengesho/sentinel.git
cd sentinel
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
sentinel --help
```

To build a local container image:

```bash
docker build -t sentinel .
docker run --rm sentinel --help
```

## Usage

The acknowledgement is mandatory. It records that you are authorized to assess the target; it does not substitute for the target program's written scope or rate limits.

```bash
sentinel scan https://example.com --authorized --format html --output reports/example
```

Use a lower rate if the program requires it:

```bash
sentinel scan example.com --authorized --rate 0.5 --no-port-scan
```

Passive CT lookup sends the domain name to crt.sh. It is opt-in:

```bash
sentinel scan example.com --authorized --passive-subdomains
```

Triage CT-discovered subdomains for takeover candidates with DNS-only checks. This
requires `--passive-subdomains` and never connects to or claims third-party services:

```bash
sentinel scan example.com --authorized --passive-subdomains --takeover-check
```

WHOIS is opt-in; SPF/DMARC DNS checks are enabled by default and can be disabled:

```bash
sentinel scan example.com --authorized --whois
sentinel scan example.com --authorized --no-email-security
```

Optionally delegate to locally installed reconnaissance tools. Each adapter is opt-in,
invoked with a bounded timeout, and respects the selected scope and rate settings:

```bash
sentinel scan example.com --authorized --subfinder --amass --nmap
sentinel scan example.com --authorized --nuclei --ffuf --wordlist ./wordlists/safe.txt
```

Public artifact checks are opt-in. They request only `/favicon.ico`,
`/.well-known/security.txt`, and `/security.txt` on the exact selected host:

```bash
sentinel scan example.com --authorized --public-artifacts --rate 0.5
```

Use custom branding for an HTML deliverable without changing scan data:

```bash
sentinel scan example.com --authorized --format html --brand-name "Acme Security" \
  --logo-url https://assets.example/logo.svg --output reports/acme-assessment
```

Content discovery is also opt-in and requires a user-supplied, scope-appropriate wordlist:

```bash
sentinel scan example.com --authorized --content-discovery --wordlist ./wordlists/safe.txt --rate 0.5
```

Use a scope manifest to prevent requests outside an approved program. The scope's rate limit is
an upper bound, even if a CLI profile requests a faster rate:

```bash
sentinel scan https://app.example.com --authorized --scope examples/authorized-scope.yaml \
  --crawl --crawl-pages 20 --crawl-depth 2 --format html --output reports/app
sentinel batch examples/authorized-scope.yaml --authorized --format json --output-dir reports/program
```

Batch scans run manifest targets sequentially by design, preserving the declared rate limit.

Monitor the explicit scope targets concurrently with one shared rate limit. The first run records
the local baseline; later runs print only newly observed targets, status changes, and reliable
`Content-Length` changes:

```bash
sentinel monitor examples/authorized-scope.yaml --authorized --state .sentinel/assets.db \
  --concurrency 4 --rate 0.5
```

The monitor sends one direct GET per explicit target, does not follow redirects or read response
bodies, and derives its compact technology hints from response headers only.

For a private training lab only, use a profile or explicit acknowledgement:

```bash
sentinel scan https://localhost:8443 --authorized --allow-private --no-port-scan
```

Keep local history for an authorized target, compare two saved scans, or export its graph data:

```bash
sentinel scan https://example.com --authorized --workspace .sentinel/research.db
sentinel workspace history .sentinel/research.db
sentinel workspace compare .sentinel/research.db 1 2 --output reports/change-report.json
sentinel workspace graph .sentinel/research.db 2 --output reports/knowledge-graph.json
```

See [the user guide](docs/user-guide.md) for all operational details, [the developer guide](docs/developer-guide.md) for local development, and [the plugin guide](docs/plugin-guide.md) for the trusted plugin interface. The [enterprise roadmap and safety boundary](docs/enterprise-roadmap.md) distinguishes delivered features from planned, safe future phases.

Maintainers should follow the [publishing guide](docs/publishing.md) before tagging a release.

## Safety model

Sentinel requires `--authorized`, limits itself to the exact selected hostname, blocks private/reserved IP literals by default, rejects DNS names with any private or reserved resolved address, follows only same-host redirects, and limits concurrency, request rate, redirects, response size, sitemap URLs, JavaScript downloads, ports, wordlist requests, and opt-in crawl pages. An unresolved domain is left to its DNS module so a transient lookup is visible in the report; requests remain exact-host scoped. A selected scope manifest adds a second enforcement layer for approved hosts and excluded paths.

Findings are observations. Reproduce them manually in accordance with the program's rules, assess impact, and do not report unverified scanner output as a vulnerability.

## Quality checks

```bash
make format
make check
```

## License

MIT. See [LICENSE](LICENSE).
