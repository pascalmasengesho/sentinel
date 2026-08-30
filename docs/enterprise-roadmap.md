# Enterprise roadmap and safety boundary

Sentinel is an authorized-security-assessment assistant. It is deliberately not an
exploitation framework: it does not brute-force credentials, bypass authentication,
evade security controls, change remote state, or perform denial-of-service testing.
Every future capability must preserve that boundary.

## Delivered in the enterprise reporting upgrade

- Responsive, self-contained HTML assessment reports with a dark/light theme,
  printable layout, custom branding, severity visualization, search, filters, and
  sortable findings.
- Executive summary, risk prioritization, timeline, module health, target/configuration
  context, and structured module summaries derived from the existing scan result.
- An Investigation Assistant for each observation: confidence, triage, supporting
  evidence, likely implications, safe manual-verification steps, missing evidence,
  relevant secure-development references, and a report-drafting checklist.
- Presentation-only metrics for published sitemap URLs, visible technology indicators,
  bounded port observations, cookies, DNS records, and normal TLS certificate
  availability. These never trigger extra requests.
- Opt-in public-artifact metadata: a same-host favicon hash and published
  `security.txt` metadata, each rate-limited through Sentinel's existing HTTP client.
- Expanded passive root-response technology hints for CMS, frameworks, libraries,
  analytics, CDN/edge, WAF, reverse proxy/container, web-server, and
  `X-Powered-By` indicators.
- Optional local SQLite research workspaces with immutable scan snapshots, scan history,
  local notes/tags/favorites, deterministic comparison, and visualization-neutral knowledge-graph
  export. Workspace data is never transmitted by Sentinel.
- A deterministic Research Prioritization Engine that correlates observed authentication, API,
  client-side, passive-asset, and public-metadata signals into safe manual-review queues.
- Local YAML scope manifests with allow-listed host patterns, excluded hosts/path prefixes, rate
  caps, reportable scope context, and sequential batch scans of explicit authorized targets.
- An opt-in bounded crawler that follows same-host, query-free HTML navigation links by GET only,
  with page/depth limits and conservative robots.txt Disallow handling.
- High-signal proprietary JavaScript static triage with exact script-source provenance for route,
  query-flag, S3-reference, and internal-style header observations. It avoids generic token lists,
  skips recognizable vendor frameworks, and redacts database URI markers.
- Local asynchronous asset delta tracking: direct header-only target probes, shared rate/concurrency
  controls, target-level failure isolation, SQLite baselines, and Markdown output for new/status/size
  changes only.

## Planned safe phases

| Stage | Scope | Guardrails |
| --- | --- | --- |
| Safe discovery refinement | Canonical URL normalization and duplicate-content detection for the delivered bounded crawler. | Off by default; no login flows, form submission, or unrestricted crawling. |
| Workspace refinement | Resume metadata, scheduled local rescans, screenshot evidence, bookmarks, richer search, and an interactive graph viewer over the existing local graph export. | Local-only by default; no central collection of target data, and screenshot capture remains explicit opt-in. |
| Evidence workflow | Opt-in screenshots of public pages, redaction-aware evidence bundles, and bug-bounty report templates. | No authenticated capture or sensitive-data collection without explicit user action. |
| Team deployment | Optional web dashboard, REST API, authentication, roles, notes, queueing, and live progress. | Separate deployment profile, secure defaults, auditable access controls, and no new active checks. |
| Distribution and operations | Release automation, package verification, container hardening, upgrade notices, and user documentation. | Publish only artifacts that pass the quality gate and preserve the authorized-use notice. |

## Acceptance criteria for future modules

Before a module is enabled by default, it must have bounded concurrency and rate
limits, target/scope validation, retry and error behavior, a documented data-retention
policy, unit tests, and a clear statement of why it is non-destructive. Modules that
could trigger meaningful state changes must remain opt-in or be excluded.
