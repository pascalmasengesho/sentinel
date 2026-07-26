# Sentinel

Sentinel is a Linux-friendly command-line assistant for **authorized** web security assessments. It combines safe, rate-limited reconnaissance and non-destructive configuration checks into evidence-oriented reports.

It is not an exploitation framework. Sentinel does not authenticate, bypass access controls, evade monitoring, submit forms, mutate data, run denial-of-service techniques, enumerate cipher suites, or try credentials. You must have permission and comply with the program's scope before scanning.

## Features

- Target validation, exact-host HTTP scope control, and private-address protection
- DNS records, wildcard-DNS indication, and resolver-provided DNSSEC AD flag
- Optional passive CT subdomain lookup and public WHOIS metadata
- Bounded TCP-connect scan, with optional banner reads only when a service sends one first
- Root HTTP, security headers, cookies, redirects, cache/compression, and advertised methods
- Normal TLS handshake/certificate metadata; it deliberately does not force legacy protocols or enumerate ciphers
- robots.txt and sitemap parsing without requesting robots-disallowed pages
- Same-origin JavaScript review for endpoint candidates and redacted secret-like patterns
- Passive technology, CDN, WAF, and hosting hints
- Optional, low-rate public API-document and user-wordlist content discovery
- JSON, Markdown, HTML, CSV, and PDF reporting; YAML profiles; trusted local plugins

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

Content discovery is also opt-in and requires a user-supplied, scope-appropriate wordlist:

```bash
sentinel scan example.com --authorized --content-discovery --wordlist ./wordlists/safe.txt --rate 0.5
```

For a private training lab only, use a profile or explicit acknowledgement:

```bash
sentinel scan https://localhost:8443 --authorized --allow-private --no-port-scan
```

See [the user guide](docs/user-guide.md) for all operational details, [the developer guide](docs/developer-guide.md) for local development, and [the plugin guide](docs/plugin-guide.md) for the trusted plugin interface.

Maintainers should follow the [publishing guide](docs/publishing.md) before tagging a release.

## Safety model

Sentinel requires `--authorized`, limits itself to the exact selected hostname, blocks private/reserved IP literals by default, follows only same-host redirects, and limits concurrency, request rate, redirects, response size, sitemap URLs, JavaScript downloads, ports, and wordlist requests. An unresolved domain is left to its DNS module so a transient lookup is visible in the report; requests remain exact-host scoped.

Findings are observations. Reproduce them manually in accordance with the program's rules, assess impact, and do not report unverified scanner output as a vulnerability.

## Quality checks

```bash
make format
make check
```

## License

MIT. See [LICENSE](LICENSE).
