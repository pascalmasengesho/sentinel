# Changelog

## 0.3.0 - 2026-08-30

- Added local YAML program-scope manifests with host/path exclusions, rate caps, and enforced
  scope context in reports.
- Added an opt-in bounded same-host crawler and sequential manifest batch scans.
- Added high-signal JavaScript structural triage with script-source provenance, vendor filtering,
  route/query/S3/header mapping, and redacted database-URI markers.
- Added asynchronous header-only asset monitoring with shared throttling, SQLite baselines, and
  Markdown summaries for new/status/size deltas only.
- Added passive SPF/DMARC email-policy checks and DNS-only subdomain-takeover triage for
  CT-discovered names; takeover triage never connects to third-party services.
- Made WHOIS opt-in (`--whois`), added strict configuration type/bounds validation, hardened
  the private-address guard to reject mixed public/private DNS answers, and fixed robots.txt
  Disallow prefix matching to follow the standard.
- Expanded technology fingerprints for CMS, frameworks, analytics, CDN/WAF, and hosting hints.
- Added opt-in adapters for locally installed external tools: subfinder, amass, nmap, nuclei,
  and ffuf, with bounded timeouts, scope/rate pass-through, and parsed report output.
- Added a combined Discovery Inventory section to HTML reports that aggregates subdomains,
  endpoints, URLs, open ports, technologies, email policy, takeover candidates, and artifacts,
  plus full per-module data tables.

## 0.2.0 - 2026-08-11

- Added enterprise HTML reporting with executive summaries, severity badges, charts,
  investigation checklists, print styling, theme controls, filtering, and branding.
- Added offline JSON-to-report rendering and explicit target URL validation.
- Added an optional local SQLite workspace with scan history, comparisons, notes, tags,
  favorites, and a local asset knowledge graph.
- Added safe HTTP posture analysis for cookie attributes, advertised methods, CSP, and HSTS.
- Added root-page-only discovery of public forms, authentication entry points, GraphQL
  references, and WebSocket references without submitting, authenticating, or connecting.
- Added deterministic research-priority guidance based solely on collected evidence.
- Added PyPI, Docker Hub, Snap Store, and AUR packaging and publication automation,
  including the continuous-integration import-classification correction.

## 0.1.0 - 2026-07-22

- Initial release with safe reconnaissance modules, reporting, configuration profiles, plugins, tests, CI, Docker, and documentation.
