# User guide

## Authorization and scope

Only run Sentinel against assets you are explicitly permitted to assess. Pass `--authorized` only after confirming the bug-bounty program or engagement permits the chosen hostname, ports, techniques, and request volume. Sentinel's safeguards supplement—not replace—those rules.

The selected hostname is the HTTP scope. Redirects, JavaScript, sitemap documents, and wordlist paths that leave that host are blocked. Private or reserved address targets require `--allow-private`, intended only for your own lab.

## Standard scan

```bash
sentinel scan https://app.example.com --authorized --format markdown --output reports/app
```

The scan performs DNS, a root HTTP request and an OPTIONS request, normal TLS metadata collection for HTTPS, a small TCP-connect scan, robots/sitemap parsing, root-page technology/header inspection, and same-host scripts. Default request starts are limited to one per second.

## Optional features

`--passive-subdomains` queries crt.sh. This is passive with respect to the target but shares the domain name with that public service.

`--api-probe` checks only `/openapi.json`, `/swagger.json`, `/api-docs`, and `/graphql`; it makes GET requests and reports 200, 401, and 403 responses. Enable it only if those requests are in scope.

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

