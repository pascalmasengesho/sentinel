# ruff: noqa: E501
"""JSON, Markdown, HTML, CSV, and PDF report rendering."""

from __future__ import annotations

import csv
import html
import json
from collections import Counter
from enum import StrEnum
from io import StringIO
from pathlib import Path
from textwrap import wrap
from typing import Any
from urllib.parse import urlsplit

from sentinel.models import Finding, ScanReport

_SEVERITY_ORDER = ("high", "medium", "low", "info")
_SEVERITY_WEIGHTS = {"high": 25, "medium": 12, "low": 4, "info": 1}
_MODULE_ICONS = {
    "amass": "⛏",
    "api_discovery": "⌘",
    "content_discovery": "≡",
    "crawler": "↳",
    "dns": "◎",
    "email_security": "✉",
    "ffuf": "ƒ",
    "headers": "▤",
    "http": "↗",
    "javascript": "{ }",
    "nmap": "⌗",
    "nuclei": "☢",
    "plugins": "✦",
    "ports": "◌",
    "research_priorities": "◆",
    "recon": "⌁",
    "robots": "⌂",
    "sitemap": "≋",
    "scope": "⌖",
    "subfinder": "⌕",
    "surface": "◫",
    "takeover": "⌖",
    "technology": "◈",
    "tls": "◇",
    "wordlist": "≡",
}

_REPORT_STYLES = """
:root {
  color-scheme: dark;
  --bg: #09111f;
  --surface: #111d30;
  --surface-raised: #17263d;
  --surface-muted: #1d2e48;
  --text: #ecf4ff;
  --muted: #9db0c9;
  --line: #2b405e;
  --brand: #4cc9f0;
  --brand-strong: #8b5cf6;
  --high: #ff6b6b;
  --medium: #f6ad55;
  --low: #63d4a4;
  --info: #72b7ff;
  --shadow: 0 22px 48px rgba(0, 0, 0, .26);
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
:root[data-theme="light"] {
  color-scheme: light;
  --bg: #f4f7fb;
  --surface: #ffffff;
  --surface-raised: #f9fbff;
  --surface-muted: #edf3fa;
  --text: #142033;
  --muted: #61718a;
  --line: #d7e1ed;
  --brand: #0678a8;
  --brand-strong: #7047d8;
  --high: #c83f4a;
  --medium: #a35a05;
  --low: #087c55;
  --info: #276ec5;
  --shadow: 0 18px 42px rgba(35, 53, 79, .12);
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body { background: var(--bg); color: var(--text); margin: 0; line-height: 1.55; }
button, input, select { font: inherit; }
a { color: var(--brand); }
.skip-link { left: -999px; position: absolute; top: 0; }
.skip-link:focus { background: var(--surface); left: 1rem; padding: .6rem .8rem; z-index: 20; }
.shell { margin: 0 auto; max-width: 1440px; padding: 0 1.25rem 4rem; }
.cover { background: radial-gradient(circle at 90% 0, rgba(76, 201, 240, .21), transparent 33%), linear-gradient(135deg, #101d35 0%, #1c2851 50%, #612d8d 150%); border-radius: 0 0 28px 28px; box-shadow: var(--shadow); color: #fff; margin: 0 -1.25rem 2rem; min-height: 340px; padding: 1.25rem max(1.25rem, calc((100vw - 1400px) / 2)); position: relative; }
.topbar { align-items: center; display: flex; gap: 1rem; justify-content: space-between; }
.brand { align-items: center; color: inherit; display: inline-flex; font-size: 1.08rem; font-weight: 800; gap: .75rem; letter-spacing: .02em; text-decoration: none; }
.brand-mark { align-items: center; background: rgba(255,255,255,.15); border: 1px solid rgba(255,255,255,.3); border-radius: 13px; display: inline-flex; height: 38px; justify-content: center; overflow: hidden; width: 38px; }
.brand-mark img { height: 100%; object-fit: contain; width: 100%; }
.nav-actions { display: flex; flex-wrap: wrap; gap: .55rem; justify-content: flex-end; }
.button { background: rgba(255,255,255,.12); border: 1px solid rgba(255,255,255,.28); border-radius: 9px; color: inherit; cursor: pointer; padding: .48rem .75rem; }
.button:hover, .button:focus-visible { background: rgba(255,255,255,.22); outline: 2px solid var(--brand); outline-offset: 2px; }
.cover-content { display: grid; gap: 2rem; grid-template-columns: minmax(0, 1.2fr) minmax(220px, .8fr); margin: 4.5rem auto 1rem; max-width: 1400px; }
.eyebrow { color: #b8eaff; font-size: .77rem; font-weight: 800; letter-spacing: .14em; margin: 0 0 .55rem; text-transform: uppercase; }
h1 { font-size: clamp(2.1rem, 5vw, 4.3rem); letter-spacing: -.045em; line-height: 1; margin: 0 0 1rem; overflow-wrap: anywhere; }
h2 { font-size: clamp(1.35rem, 2.4vw, 2rem); letter-spacing: -.025em; margin: 0; }
h3 { font-size: 1rem; margin: 0; }
.cover-copy { color: #dce8ff; max-width: 760px; }
.metadata { color: #c1d2ec; display: flex; flex-wrap: wrap; gap: .6rem 1.25rem; font-size: .9rem; margin-top: 1.5rem; }
.risk-orb { align-items: center; align-self: center; backdrop-filter: blur(10px); background: rgba(5,12,28,.31); border: 1px solid rgba(255,255,255,.2); border-radius: 50%; display: flex; flex-direction: column; height: 212px; justify-content: center; margin: auto; text-align: center; width: 212px; }
.risk-orb strong { font-size: 3.7rem; letter-spacing: -.09em; line-height: 1; }
.risk-orb span { color: #dbeafe; font-size: .8rem; letter-spacing: .1em; text-transform: uppercase; }
.sticky-nav { backdrop-filter: blur(16px); background: color-mix(in srgb, var(--bg) 88%, transparent); border-bottom: 1px solid var(--line); position: sticky; top: 0; z-index: 10; }
.sticky-nav-inner { display: flex; gap: .3rem; margin: auto; max-width: 1440px; overflow-x: auto; padding: .7rem 1.25rem; }
.sticky-nav a { border-radius: 7px; color: var(--muted); font-size: .86rem; padding: .35rem .5rem; text-decoration: none; white-space: nowrap; }
.sticky-nav a:hover { background: var(--surface-muted); color: var(--text); }
.section { margin-top: 3rem; scroll-margin-top: 4rem; }
.section-heading { align-items: end; display: flex; gap: 1rem; justify-content: space-between; margin-bottom: 1rem; }
.section-heading p { color: var(--muted); margin: 0; max-width: 780px; }
.grid { display: grid; gap: 1rem; }
.summary-grid { grid-template-columns: repeat(4, minmax(0, 1fr)); }
.analytics-grid { grid-template-columns: minmax(280px, .8fr) minmax(0, 1.2fr); }
.card { background: var(--surface); border: 1px solid var(--line); border-radius: 16px; box-shadow: 0 8px 22px rgba(0,0,0,.07); padding: 1.15rem; }
.metric { min-height: 126px; position: relative; overflow: hidden; }
.metric::after { background: var(--metric-color, var(--brand)); border-radius: 99px; content: ""; height: 6px; left: 1.15rem; position: absolute; right: 1.15rem; top: 0; }
.metric-label { color: var(--muted); font-size: .78rem; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
.metric-value { font-size: 2.25rem; font-weight: 800; letter-spacing: -.06em; line-height: 1; margin: .65rem 0 .25rem; }
.metric-note { color: var(--muted); font-size: .87rem; margin: 0; }
.risk-card { align-items: center; display: flex; gap: 1.3rem; }
.risk-ring { align-items: center; background: conic-gradient(var(--risk-color) calc(var(--risk) * 1%), var(--surface-muted) 0); border-radius: 50%; display: flex; flex: 0 0 auto; height: 142px; justify-content: center; position: relative; width: 142px; }
.risk-ring::after { background: var(--surface); border-radius: 50%; content: ""; inset: 10px; position: absolute; }
.risk-ring span { font-size: 2.15rem; font-weight: 800; position: relative; z-index: 1; }
.risk-copy p { color: var(--muted); margin: .4rem 0 0; }
.legend { display: flex; flex-wrap: wrap; gap: .45rem; margin-top: 1rem; }
.legend-item { align-items: center; color: var(--muted); display: inline-flex; font-size: .82rem; gap: .35rem; }
.legend-dot { background: var(--dot); border-radius: 50%; height: .6rem; width: .6rem; }
.chart-wrap { min-height: 262px; position: relative; }
canvas { height: 250px; max-width: 100%; width: 100%; }
.bar-list { display: grid; gap: .78rem; }
.bar-row { align-items: center; display: grid; gap: .75rem; grid-template-columns: minmax(105px, .28fr) minmax(0, 1fr) auto; }
.bar-label { align-items: center; display: flex; gap: .45rem; min-width: 0; }
.module-icon { align-items: center; background: var(--surface-muted); border-radius: 8px; color: var(--brand); display: inline-flex; font-size: .75rem; font-weight: 800; height: 27px; justify-content: center; min-width: 27px; padding: 0 .25rem; }
.bar-track { background: var(--surface-muted); border-radius: 99px; height: 9px; overflow: hidden; }
.bar-fill { background: linear-gradient(90deg, var(--brand), var(--brand-strong)); border-radius: inherit; height: 100%; transition: width .9s ease; }
.notice { background: color-mix(in srgb, var(--info) 13%, var(--surface)); border: 1px solid color-mix(in srgb, var(--info) 40%, var(--line)); border-radius: 12px; color: var(--text); padding: 1rem 1.1rem; }
.filters { align-items: center; display: flex; flex-wrap: wrap; gap: .65rem; }
.field { background: var(--surface); border: 1px solid var(--line); border-radius: 9px; color: var(--text); min-height: 39px; padding: .42rem .65rem; }
.field:focus { border-color: var(--brand); outline: 2px solid color-mix(in srgb, var(--brand) 30%, transparent); }
.finding-list { display: grid; gap: .85rem; }
.finding { background: var(--surface); border: 1px solid var(--line); border-left: 5px solid var(--severity-color); border-radius: 13px; overflow: hidden; }
.finding[hidden] { display: none; }
.finding-summary { align-items: start; cursor: pointer; display: grid; gap: .85rem; grid-template-columns: auto minmax(0, 1fr) auto; list-style: none; padding: 1rem 1.1rem; }
.finding-summary::-webkit-details-marker { display: none; }
.finding-title { font-size: 1.05rem; font-weight: 750; margin: 0; overflow-wrap: anywhere; }
.finding-meta { color: var(--muted); font-size: .82rem; margin: .25rem 0 0; }
.badge { border: 1px solid currentColor; border-radius: 99px; color: var(--severity-color, var(--info)); display: inline-flex; font-size: .72rem; font-weight: 800; letter-spacing: .05em; padding: .18rem .47rem; text-transform: uppercase; white-space: nowrap; }
.triage { background: var(--surface-muted); border-radius: 99px; color: var(--text); display: inline-flex; font-size: .72rem; font-weight: 700; padding: .2rem .5rem; text-align: right; }
.finding-body { border-top: 1px solid var(--line); padding: 1.15rem; }
.finding-description { font-size: 1.02rem; margin-top: 0; }
.detail-grid { display: grid; gap: .85rem; grid-template-columns: repeat(2, minmax(0, 1fr)); }
.detail-box { background: var(--surface-raised); border: 1px solid var(--line); border-radius: 10px; padding: .85rem; }
.detail-box h4 { color: var(--muted); font-size: .75rem; letter-spacing: .08em; margin: 0 0 .4rem; text-transform: uppercase; }
.detail-box p, .detail-box ul { margin: 0; }
.detail-box ul { padding-left: 1.15rem; }
.evidence { background: #07101d; border: 1px solid #21334d; border-radius: 8px; color: #cae2ff; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: .84rem; max-height: 14rem; overflow: auto; padding: .75rem; white-space: pre-wrap; word-break: break-word; }
:root[data-theme="light"] .evidence { background: #172236; color: #e5f0ff; }
.copy-button { background: transparent; border: 1px solid var(--line); border-radius: 7px; color: var(--muted); cursor: pointer; font-size: .78rem; margin-top: .5rem; padding: .25rem .45rem; }
.copy-button:hover { border-color: var(--brand); color: var(--brand); }
.finding details, .module details, .raw-data { background: var(--surface-raised); border: 1px solid var(--line); border-radius: 9px; margin-top: .85rem; padding: .75rem; }
summary { cursor: pointer; font-weight: 700; }
.module-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }
.module { display: flex; flex-direction: column; gap: .8rem; min-width: 0; }
.module-head { align-items: center; display: flex; gap: .65rem; }
.module-name { font-size: 1rem; font-weight: 800; margin: 0; overflow-wrap: anywhere; }
.module-state { color: var(--muted); font-size: .8rem; margin-left: auto; }
.facts { display: grid; gap: .5rem; }
.fact { border-bottom: 1px solid color-mix(in srgb, var(--line) 65%, transparent); display: grid; gap: .5rem; grid-template-columns: minmax(90px, .32fr) minmax(0, 1fr); padding-bottom: .45rem; }
.fact:last-child { border-bottom: 0; padding-bottom: 0; }
.fact-key { color: var(--muted); font-size: .78rem; }
.value-list { display: flex; flex-wrap: wrap; gap: .3rem; }
.chip { background: var(--surface-muted); border-radius: 5px; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: .75rem; overflow-wrap: anywhere; padding: .1rem .35rem; }
.table-scroll { border: 1px solid var(--line); border-radius: 12px; overflow: auto; }
table { border-collapse: collapse; min-width: 690px; width: 100%; }
th, td { border-bottom: 1px solid var(--line); padding: .72rem .8rem; text-align: left; vertical-align: top; }
th { background: var(--surface-raised); color: var(--muted); font-size: .75rem; letter-spacing: .06em; position: sticky; text-transform: uppercase; top: 0; }
th button { background: none; border: 0; color: inherit; cursor: pointer; font: inherit; padding: 0; text-transform: inherit; }
tr:last-child td { border-bottom: 0; }
.timeline { border-left: 2px solid var(--line); display: grid; gap: .9rem; margin-left: .55rem; padding-left: 1.3rem; }
.timeline-item { position: relative; }
.timeline-item::before { background: var(--brand); border: 3px solid var(--bg); border-radius: 50%; content: ""; height: .7rem; left: -1.72rem; position: absolute; top: .35rem; width: .7rem; }
.timeline-time { color: var(--muted); font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: .78rem; }
.reference-list { display: flex; flex-wrap: wrap; gap: .45rem; margin-top: .65rem; }
.reference-list a { background: var(--surface-muted); border-radius: 6px; font-size: .78rem; padding: .25rem .45rem; text-decoration: none; }
.raw-data pre { max-height: 420px; overflow: auto; }
.footer { border-top: 1px solid var(--line); color: var(--muted); font-size: .84rem; margin-top: 3rem; padding-top: 1.5rem; }
.muted { color: var(--muted); }
.empty { color: var(--muted); font-style: italic; padding: 1rem; }
@media (max-width: 940px) { .summary-grid, .module-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } .analytics-grid, .cover-content { grid-template-columns: 1fr; } .risk-orb { margin: 0; } }
@media (max-width: 630px) { .shell { padding: 0 .85rem 3rem; } .cover { margin-left: -.85rem; margin-right: -.85rem; padding-left: .85rem; padding-right: .85rem; } .summary-grid, .module-grid, .detail-grid { grid-template-columns: 1fr; } .cover-content { margin-top: 3rem; } .finding-summary { grid-template-columns: auto minmax(0, 1fr); } .triage { grid-column: 2; justify-self: start; } .risk-card { align-items: flex-start; flex-direction: column; } .bar-row { grid-template-columns: minmax(92px, .4fr) minmax(0, 1fr) auto; } }
@media print { :root, :root[data-theme="light"] { --bg: #fff; --surface: #fff; --surface-raised: #fafafa; --text: #142033; --muted: #526173; --line: #c8d1db; --shadow: none; } body { font-size: 10pt; } .cover { background: #fff; border: 1px solid var(--line); color: var(--text); min-height: auto; padding: 1.5rem; } .cover-copy, .metadata, .eyebrow { color: var(--muted); } .nav-actions, .sticky-nav, .filters, .copy-button { display: none !important; } .section { break-inside: avoid; margin-top: 1.5rem; } .card, .finding { box-shadow: none; break-inside: avoid; } .finding { display: block !important; } .finding-body { display: block !important; } details { break-inside: avoid; } canvas { display: none; } .chart-wrap::after { color: var(--muted); content: "Charts are available in the interactive digital report."; font-style: italic; } a { color: #142033; text-decoration: none; } }
"""

_REPORT_SCRIPT = """
(() => {
  const root = document.documentElement;
  const themeButton = document.querySelector('[data-theme-toggle]');
  const savedTheme = localStorage.getItem('sentinel-theme');
  if (savedTheme) root.dataset.theme = savedTheme;
  themeButton?.addEventListener('click', () => {
    const next = root.dataset.theme === 'light' ? 'dark' : 'light';
    root.dataset.theme = next;
    localStorage.setItem('sentinel-theme', next);
    themeButton.setAttribute('aria-label', `Switch to ${next === 'light' ? 'dark' : 'light'} theme`);
  });

  const search = document.querySelector('[data-finding-search]');
  const severity = document.querySelector('[data-severity-filter]');
  const findings = [...document.querySelectorAll('[data-finding]')];
  const filterFindings = () => {
    const query = (search?.value || '').toLowerCase().trim();
    const selected = severity?.value || 'all';
    findings.forEach((item) => {
      const matchesText = item.textContent.toLowerCase().includes(query);
      const matchesSeverity = selected === 'all' || item.dataset.severity === selected;
      item.hidden = !matchesText || !matchesSeverity;
    });
  };
  search?.addEventListener('input', filterFindings);
  severity?.addEventListener('change', filterFindings);

  document.querySelectorAll('[data-copy-target]').forEach((button) => {
    button.addEventListener('click', async () => {
      const target = document.getElementById(button.dataset.copyTarget);
      if (!target) return;
      try {
        await navigator.clipboard.writeText(target.textContent || '');
        const previous = button.textContent;
        button.textContent = 'Copied';
        window.setTimeout(() => { button.textContent = previous; }, 1500);
      } catch (_) {
        button.textContent = 'Select evidence to copy';
      }
    });
  });

  const table = document.querySelector('[data-sortable-findings]');
  table?.querySelectorAll('[data-sort]').forEach((button) => {
    button.addEventListener('click', () => {
      const body = table.querySelector('tbody');
      const key = button.dataset.sort;
      const ascending = button.dataset.direction !== 'asc';
      const rows = [...body.querySelectorAll('tr')];
      rows.sort((left, right) => {
        const a = left.dataset[key] || '';
        const b = right.dataset[key] || '';
        return ascending ? a.localeCompare(b, undefined, { numeric: true }) : b.localeCompare(a, undefined, { numeric: true });
      });
      rows.forEach((row) => body.appendChild(row));
      table.querySelectorAll('[data-sort]').forEach((item) => { item.dataset.direction = ''; });
      button.dataset.direction = ascending ? 'asc' : 'desc';
    });
  });

  document.querySelector('[data-export-json]')?.addEventListener('click', () => {
    const source = document.getElementById('scan-data');
    if (!source) return;
    const blob = new Blob([source.textContent || '{}'], { type: 'application/json' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'sentinel-scan-data.json';
    link.click();
    URL.revokeObjectURL(link.href);
  });

  const chart = document.querySelector('[data-severity-chart]');
  const scanData = document.getElementById('scan-data');
  if (!chart || !scanData || !chart.getContext) return;
  const data = JSON.parse(scanData.textContent || '{}');
  const stats = data.statistics || {};
  const entries = [
    ['high', Number(stats.high || 0), '#ff6b6b'],
    ['medium', Number(stats.medium || 0), '#f6ad55'],
    ['low', Number(stats.low || 0), '#63d4a4'],
    ['info', Number(stats.info || 0), '#72b7ff'],
  ];
  const total = entries.reduce((sum, entry) => sum + entry[1], 0);
  const context = chart.getContext('2d');
  const size = Math.min(chart.clientWidth || 260, 260);
  const pixelRatio = window.devicePixelRatio || 1;
  chart.width = size * pixelRatio;
  chart.height = size * pixelRatio;
  context.scale(pixelRatio, pixelRatio);
  const center = size / 2;
  const radius = size * .34;
  let angle = -Math.PI / 2;
  if (total) {
    entries.forEach(([, count, color]) => {
      const slice = (count / total) * Math.PI * 2;
      context.beginPath();
      context.arc(center, center, radius, angle, angle + slice);
      context.strokeStyle = color;
      context.lineWidth = Math.max(18, size * .12);
      context.stroke();
      angle += slice;
    });
  } else {
    context.beginPath();
    context.arc(center, center, radius, 0, Math.PI * 2);
    context.strokeStyle = '#60738c';
    context.lineWidth = Math.max(18, size * .12);
    context.stroke();
  }
  context.fillStyle = getComputedStyle(root).getPropertyValue('--text');
  context.font = `700 ${Math.round(size * .16)}px system-ui`;
  context.textAlign = 'center';
  context.fillText(String(total), center, center + 3);
  context.fillStyle = getComputedStyle(root).getPropertyValue('--muted');
  context.font = `600 ${Math.round(size * .055)}px system-ui`;
  context.fillText('FINDINGS', center, center + size * .12);
})();
"""


class ReportFormat(StrEnum):
    """Supported report formats."""

    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"
    CSV = "csv"
    PDF = "pdf"


_EXTENSIONS = {
    ReportFormat.JSON: ".json",
    ReportFormat.MARKDOWN: ".md",
    ReportFormat.HTML: ".html",
    ReportFormat.CSV: ".csv",
    ReportFormat.PDF: ".pdf",
}


class ReportWriter:
    """Write report artifacts and return their final paths."""

    def __init__(
        self,
        brand_name: str = "Sentinel",
        logo_url: str = "",
        config_snapshot: dict[str, Any] | None = None,
    ) -> None:
        """Configure report presentation metadata without changing scan data."""
        self.brand_name = brand_name.strip() or "Sentinel"
        self.logo_url = logo_url.strip()
        self.config_snapshot = dict(config_snapshot or {})

    def write(self, report: ScanReport, output: Path, report_format: ReportFormat) -> Path:
        """Render a report, adding the appropriate suffix when needed."""
        output.parent.mkdir(parents=True, exist_ok=True)
        final_path = output if output.suffix else output.with_suffix(_EXTENSIONS[report_format])
        if report_format is ReportFormat.JSON:
            final_path.write_text(
                json.dumps(report.as_dict(), indent=2, default=str), encoding="utf-8"
            )
        elif report_format is ReportFormat.MARKDOWN:
            final_path.write_text(self.to_markdown(report), encoding="utf-8")
        elif report_format is ReportFormat.HTML:
            final_path.write_text(self.to_html(report), encoding="utf-8")
        elif report_format is ReportFormat.CSV:
            final_path.write_text(self.to_csv(report), encoding="utf-8", newline="")
        elif report_format is ReportFormat.PDF:
            self.to_pdf(report, final_path)
        else:  # pragma: no cover - StrEnum is exhaustive, retained for defensive use.
            raise ValueError(f"Unsupported report format: {report_format}")
        return final_path

    @staticmethod
    def findings(report: ScanReport) -> list[Finding]:
        """Flatten report findings while retaining each finding's origin module."""
        return [finding for module in report.modules for finding in module.findings]

    def to_markdown(self, report: ScanReport) -> str:
        """Render a concise, portable Markdown report."""
        statistics = report.statistics
        summary_row = (
            f"| {statistics.get('modules_run', 0)} | {statistics.get('findings', 0)} | "
            f"{statistics.get('errors', 0)} | {statistics.get('high', 0)} | "
            f"{statistics.get('medium', 0)} | {statistics.get('low', 0)} |"
        )
        lines = [
            "# Sentinel assessment report",
            "",
            f"- **Target:** `{report.target}`",
            f"- **Started:** {report.started_at}",
            f"- **Finished:** {report.finished_at}",
            f"- **Authorized acknowledgement:** {report.authorized}",
            "",
            "> " + report.notice,
            "",
            "## Summary",
            "",
            "| Modules | Findings | Errors | High | Medium | Low |",
            "| ---: | ---: | ---: | ---: | ---: | ---: |",
            summary_row,
            "",
            "## Findings",
            "",
        ]
        findings = self.findings(report)
        if not findings:
            lines.append("No reportable observations were produced.")
        for index, finding in enumerate(findings, start=1):
            lines.extend(
                [
                    f"### {index}. [{finding.severity.upper()}] {finding.title}",
                    "",
                    finding.description,
                    "",
                    f"- **Module:** {finding.module}",
                    f"- **Evidence:** {finding.evidence}",
                    f"- **Recommendation:** {finding.recommendation}",
                    f"- **CVSS:** {finding.cvss or 'Not scored'}",
                    "",
                ]
            )
        lines.extend(["## Module data", ""])
        for module in report.modules:
            lines.extend(
                [
                    f"### {module.module}",
                    "",
                    "```json",
                    json.dumps(module.data, indent=2, default=str),
                    "```",
                    "",
                ]
            )
            if module.errors:
                lines.extend(["Errors:", *[f"- {error}" for error in module.errors], ""])
        return "\n".join(lines)

    def to_html(self, report: ScanReport) -> str:
        """Render a self-contained interactive report from unchanged scan results."""
        findings = self.findings(report)
        severity_counts = self._severity_counts(findings)
        risk_score = self._risk_score(severity_counts)
        risk_label, risk_color = self._risk_label(risk_score)
        finding_cards = (
            "".join(
                self._finding_card(finding, index)
                for index, finding in enumerate(findings, start=1)
            )
            or '<p class="empty">No reportable observations were produced.</p>'
        )
        finding_rows = "".join(self._finding_row(finding) for finding in findings) or (
            '<tr><td colspan="5" class="empty">No observations were produced.</td></tr>'
        )
        module_cards = "".join(self._module_card(module) for module in report.modules) or (
            '<p class="empty">No module output is available.</p>'
        )
        module_bars = self._module_bars(report)
        timeline = self._timeline(report)
        scan_json = self._json_for_html(report.as_dict())
        target = self._escape(report.target)
        brand = self._escape(self.brand_name)
        logo = self._logo_markup()
        safe_target_url = self._safe_url(report.target)
        target_link = (
            f'<a href="{self._escape(safe_target_url)}" rel="noreferrer">{target}</a>'
            if safe_target_url
            else target
        )
        findings_total = len(findings)
        modules_total = len(report.modules)
        errors_total = sum(len(module.errors) for module in report.modules)
        duration = sum(module.duration_ms for module in report.modules)
        metrics = self._scan_metrics(report)
        configuration_facts = self._data_facts(self.config_snapshot)
        priority_cards = self._priority_cards(report)
        severity_legend = "".join(
            self._severity_legend(level, severity_counts[level]) for level in _SEVERITY_ORDER
        )

        return f"""<!doctype html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark light">
  <title>{brand} security assessment — {target}</title>
  <style>{_REPORT_STYLES}</style>
</head>
<body>
  <a class="skip-link" href="#findings">Skip to findings</a>
  <header class="cover" id="overview">
    <div class="topbar">
      <span class="brand">{logo}<span>{brand}</span></span>
      <div class="nav-actions" aria-label="Report actions">
        <button class="button" type="button" data-export-json>Export JSON</button>
        <button class="button" type="button" onclick="window.print()">Print / Save PDF</button>
        <button class="button" type="button" data-theme-toggle aria-label="Switch theme">Theme</button>
      </div>
    </div>
    <div class="cover-content">
      <div>
        <p class="eyebrow">Authorized security assessment</p>
        <h1>{target_link}</h1>
        <p class="cover-copy">Enterprise-style reconnaissance report for authorized assessment work. Findings are observations, not proof of exploitability.</p>
        <div class="metadata">
          <span><strong>Started:</strong> {self._escape(report.started_at)}</span>
          <span><strong>Finished:</strong> {self._escape(report.finished_at)}</span>
          <span><strong>Version:</strong> {self._escape(report.version)}</span>
          <span><strong>Authorization:</strong> {"Acknowledged" if report.authorized else "Not acknowledged"}</span>
        </div>
      </div>
      <div class="risk-orb" aria-label="Overall risk score {risk_score} out of 100">
        <strong>{risk_score}</strong><span>{risk_label} risk</span>
      </div>
    </div>
  </header>

  <nav class="sticky-nav" aria-label="Report navigation"><div class="sticky-nav-inner">
    <a href="#overview">Overview</a><a href="#risk">Risk</a><a href="#findings">Findings</a>
    <a href="#priorities">Priorities</a><a href="#investigation">Investigation Assistant</a><a href="#configuration">Configuration</a><a href="#modules">Modules</a>
    <a href="#timeline">Timeline</a><a href="#appendix">Appendix</a>
  </div></nav>

  <main class="shell">
    <section class="section" aria-labelledby="executive-summary">
      <div class="section-heading"><div><h2 id="executive-summary">Executive summary</h2><p>Scope is limited to the selected target and the configured, non-destructive checks.</p></div></div>
      <div class="notice"><strong>Assessment posture:</strong> {self._escape(report.notice)} No confirmed reportable vulnerability has been identified from passive reconnaissance alone.</div>
      <div class="grid summary-grid" style="margin-top:1rem">
        <article class="card metric" style="--metric-color:var(--brand)"><span class="metric-label">Total observations</span><div class="metric-value">{findings_total}</div><p class="metric-note">Across {modules_total} assessment modules</p></article>
        <article class="card metric" style="--metric-color:var(--info)"><span class="metric-label">Critical severity</span><div class="metric-value">0</div><p class="metric-note">The current data model does not classify critical findings</p></article>
        <article class="card metric" style="--metric-color:var(--high)"><span class="metric-label">High severity</span><div class="metric-value">{severity_counts["high"]}</div><p class="metric-note">Require careful manual validation</p></article>
        <article class="card metric" style="--metric-color:var(--medium)"><span class="metric-label">Needs investigation</span><div class="metric-value">{severity_counts["medium"]}</div><p class="metric-note">Evidence is not exploitation proof</p></article>
        <article class="card metric" style="--metric-color:var(--low)"><span class="metric-label">Low severity</span><div class="metric-value">{severity_counts["low"]}</div><p class="metric-note">Often contextual hardening observations</p></article>
        <article class="card metric" style="--metric-color:var(--info)"><span class="metric-label">Informational</span><div class="metric-value">{severity_counts["info"]}</div><p class="metric-note">Useful security posture context</p></article>
        <article class="card metric" style="--metric-color:var(--brand-strong)"><span class="metric-label">URLs discovered</span><div class="metric-value">{metrics["urls"]}</div><p class="metric-note">Published sitemap URLs only</p></article>
        <article class="card metric" style="--metric-color:var(--brand)"><span class="metric-label">Technologies observed</span><div class="metric-value">{metrics["technologies"]}</div><p class="metric-note">Visible root-response indicators</p></article>
        <article class="card metric" style="--metric-color:var(--brand-strong)"><span class="metric-label">Open ports</span><div class="metric-value">{metrics["ports"]}</div><p class="metric-note">Bounded TCP-connect observations</p></article>
        <article class="card metric" style="--metric-color:var(--low)"><span class="metric-label">Module health</span><div class="metric-value">{modules_total - errors_total}/{modules_total}</div><p class="metric-note">{errors_total} module error(s) recorded</p></article>
      </div>
    </section>

    <section class="section" id="risk" aria-labelledby="risk-heading">
      <div class="section-heading"><div><h2 id="risk-heading">Risk overview</h2><p>A transparent prioritization aid based only on observed severity counts; it is not a vulnerability score.</p></div></div>
      <div class="grid analytics-grid">
        <article class="card risk-card"><div class="risk-ring" style="--risk:{risk_score};--risk-color:{risk_color}"><span>{risk_score}</span></div><div class="risk-copy"><h3>{risk_label} observed risk</h3><p>High findings contribute 25 points, medium 12, low 4, and informational 1. The result is capped at 100 and must be validated in scope.</p><div class="legend">{severity_legend}</div></div></article>
        <article class="card"><h3>Severity distribution</h3><div class="chart-wrap"><canvas data-severity-chart aria-label="Severity distribution chart" role="img"></canvas></div><div class="legend">{severity_legend}</div></article>
      </div>
      <article class="card" style="margin-top:1rem"><h3>Module execution profile</h3><div class="bar-list" style="margin-top:1rem">{module_bars}</div></article>
    </section>

    <section class="section" id="priorities" aria-labelledby="priorities-heading">
      <div class="section-heading"><div><h2 id="priorities-heading">Research priorities</h2><p>Deterministic correlation of completed scan data to guide safe manual investigation. These are not vulnerability claims.</p></div></div>
      <div class="grid module-grid">{priority_cards}</div>
    </section>

    <section class="section" id="findings" aria-labelledby="findings-heading">
      <div class="section-heading"><div><h2 id="findings-heading">Technical findings</h2><p>Expand an observation to view evidence, safe verification guidance, and report-writing context.</p></div></div>
      <div class="filters" aria-label="Finding filters"><input class="field" type="search" data-finding-search placeholder="Search title, evidence, module…" aria-label="Search findings"><select class="field" data-severity-filter aria-label="Filter by severity"><option value="all">All severities</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="info">Informational</option></select></div>
      <div class="finding-list" style="margin-top:1rem">{finding_cards}</div>
      <div class="table-scroll" style="margin-top:1rem"><table data-sortable-findings><thead><tr><th><button type="button" data-sort="severity">Severity ↕</button></th><th><button type="button" data-sort="title">Finding ↕</button></th><th><button type="button" data-sort="module">Module ↕</button></th><th>Triage</th><th>Evidence summary</th></tr></thead><tbody>{finding_rows}</tbody></table></div>
    </section>

    <section class="section" id="investigation" aria-labelledby="investigation-heading">
      <div class="section-heading"><div><h2 id="investigation-heading">Investigation Assistant</h2><p>Use these safe, manual next steps to decide whether an observation is meaningful within the program’s scope.</p></div></div>
      <div class="grid analytics-grid"><article class="card"><h3>How to use this report</h3><ol><li>Confirm the target is in scope and record the relevant program rule.</li><li>Reproduce the observation manually without bypassing controls or changing data.</li><li>Capture the missing evidence and assess realistic impact.</li><li>Only submit a report when the issue is confirmed and not already known.</li></ol></article><article class="card"><h3>Report readiness</h3><p><strong>Current conclusion:</strong> No confirmed reportable vulnerability has been identified from passive reconnaissance alone.</p><p class="muted">Each finding includes a triage label, evidence collected, evidence still missing, and a safe report-drafting checklist.</p></article></div>
    </section>

    <section class="section" id="configuration" aria-labelledby="configuration-heading">
      <div class="section-heading"><div><h2 id="configuration-heading">Assessment configuration</h2><p>Target and runtime settings captured for reproducibility. This presentation metadata does not alter the machine-readable scan record.</p></div></div>
      <div class="grid analytics-grid"><article class="card"><h3>Target information</h3><div class="facts"><div class="fact"><span class="fact-key">Target</span><span>{target_link}</span></div><div class="fact"><span class="fact-key">Authorized acknowledgement</span><span>{"Yes" if report.authorized else "No"}</span></div><div class="fact"><span class="fact-key">Sentinel version</span><span>{self._escape(report.version)}</span></div><div class="fact"><span class="fact-key">TLS certificate observed</span><span>{metrics["certificates"]}</span></div></div></article><article class="card"><h3>Scan configuration</h3><div class="facts">{configuration_facts}</div></article></div>
    </section>

    <section class="section" id="modules" aria-labelledby="modules-heading">
      <div class="section-heading"><div><h2 id="modules-heading">Structured module summaries</h2><p>Key module data is presented as readable facts. The unchanged raw scan JSON remains available in the appendix.</p></div></div>
      <div class="grid module-grid">{module_cards}</div>
    </section>

    <section class="section" id="timeline" aria-labelledby="timeline-heading"><div class="section-heading"><div><h2 id="timeline-heading">Scan execution timeline</h2><p>Module durations are measured by Sentinel; total module time is {duration} ms.</p></div></div><div class="timeline">{timeline}</div></section>

    <section class="section" id="appendix" aria-labelledby="appendix-heading"><div class="section-heading"><div><h2 id="appendix-heading">Appendix</h2><p>Machine-readable scan data is retained intact for evidence preservation and export.</p></div></div><details class="raw-data"><summary>View raw scan JSON</summary><pre class="evidence">{self._escape(json.dumps(report.as_dict(), indent=2, default=str))}</pre></details></section>

    <footer class="footer"><strong>{brand}</strong> · Authorized, non-destructive reconnaissance assistance · Generated from Sentinel version {self._escape(report.version)}</footer>
  </main>
  <script id="scan-data" type="application/json">{scan_json}</script>
  <script>{_REPORT_SCRIPT}</script>
</body>
</html>"""

    @staticmethod
    def _escape(value: object) -> str:
        return html.escape(str(value), quote=True)

    @staticmethod
    def _severity(finding: Finding) -> str:
        level = str(finding.severity).lower()
        return level if level in _SEVERITY_ORDER else "info"

    def _severity_counts(self, findings: list[Finding]) -> dict[str, int]:
        counts = Counter(self._severity(finding) for finding in findings)
        return {level: counts[level] for level in _SEVERITY_ORDER}

    def _priority_cards(self, report: ScanReport) -> str:
        """Render deterministic research priorities without turning them into findings."""
        priority_module = next(
            (module for module in report.modules if module.module == "research_priorities"),
            None,
        )
        if priority_module is None:
            return '<p class="empty">No cross-module priorities were generated for this scan.</p>'
        priorities = priority_module.data.get("priorities", [])
        if not isinstance(priorities, list) or not priorities:
            return '<p class="empty">No manual-investigation priorities were generated from the observed data.</p>'
        cards = []
        for priority in priorities:
            if not isinstance(priority, dict):
                continue
            title = self._escape(priority.get("title", "Research priority"))
            tier = self._escape(priority.get("tier", "Manual review"))
            confidence = self._escape(priority.get("confidence", "Observed context"))
            next_step = self._escape(priority.get("safe_next_step", "Validate manually in scope."))
            evidence = priority.get("evidence", [])
            evidence_items = (
                self._list_items([str(item) for item in evidence])
                if isinstance(evidence, list)
                else ""
            )
            cards.append(
                f"""<article class="card module"><div class="module-head"><span class="module-icon" aria-hidden="true">◆</span><h3 class="module-name">{title}</h3><span class="module-state">{tier}</span></div><p class="muted">Confidence: {confidence}</p><details open><summary>Observed context</summary><ul>{evidence_items}</ul></details><details><summary>Safe next step</summary><p>{next_step}</p></details></article>"""
            )
        return "".join(cards) or '<p class="empty">No valid research priorities were generated.</p>'

    @staticmethod
    def _scan_metrics(report: ScanReport) -> dict[str, int]:
        """Summarize existing module data without changing it or making new requests."""
        module_data = {module.module: module.data for module in report.modules}
        sitemap = module_data.get("sitemap", {})
        technology = module_data.get("technology", {})
        ports = module_data.get("ports", {})
        http = module_data.get("http", {})
        dns = module_data.get("dns", {})
        tls = module_data.get("tls", {})
        dns_records = dns.get("records", {}) if isinstance(dns, dict) else {}
        technologies = technology.get("technologies", []) if isinstance(technology, dict) else []
        open_ports = ports.get("open_ports", []) if isinstance(ports, dict) else []
        cookie_names = http.get("cookie_names", []) if isinstance(http, dict) else []
        return {
            "urls": int(sitemap.get("url_count", 0)) if isinstance(sitemap, dict) else 0,
            "technologies": len(technologies) if isinstance(technologies, list) else 0,
            "ports": len(open_ports) if isinstance(open_ports, list) else 0,
            "cookies": len(cookie_names) if isinstance(cookie_names, list) else 0,
            "dns_records": sum(
                len(values) for values in dns_records.values() if isinstance(values, list)
            ),
            "certificates": int(bool(tls.get("applicable"))) if isinstance(tls, dict) else 0,
        }

    @staticmethod
    def _risk_score(counts: dict[str, int]) -> int:
        return min(100, sum(counts[level] * _SEVERITY_WEIGHTS[level] for level in _SEVERITY_ORDER))

    @staticmethod
    def _risk_label(score: int) -> tuple[str, str]:
        if score >= 70:
            return "High", "var(--high)"
        if score >= 35:
            return "Elevated", "var(--medium)"
        if score >= 10:
            return "Guarded", "var(--low)"
        return "Minimal", "var(--info)"

    def _severity_legend(self, level: str, count: int) -> str:
        return (
            f'<span class="legend-item"><span class="legend-dot" style="--dot:var(--{level})"></span>'
            f"{self._escape(level.title())}: {count}</span>"
        )

    def _finding_card(self, finding: Finding, index: int) -> str:
        severity = self._severity(finding)
        confidence = self._confidence(finding)
        triage = self._triage(finding)
        evidence_id = f"finding-evidence-{index}"
        module = self._escape(finding.module)
        references = self._references(finding)
        details = self._technical_details(finding)
        return f"""<details class="finding" data-finding data-severity="{severity}" style="--severity-color:var(--{severity})">
  <summary class="finding-summary"><span class="badge">{self._escape(severity)}</span><span><span class="finding-title">{self._escape(finding.title)}</span><span class="finding-meta">Module: {module} · Confidence: {self._escape(confidence)}</span></span><span class="triage">{self._escape(triage)}</span></summary>
  <div class="finding-body">
    <p class="finding-description">{self._escape(finding.description)}</p>
    <div class="detail-grid">
      <section class="detail-box"><h4>Why it could matter</h4><p>{self._escape(self._why_it_matters(finding))}</p></section>
      <section class="detail-box"><h4>Potential security implications</h4><p>{self._escape(self._implications(finding))}</p></section>
      <section class="detail-box"><h4>Safe manual verification</h4><ul>{self._list_items(self._verification_steps(finding))}</ul></section>
      <section class="detail-box"><h4>Evidence still needed</h4><p>{self._escape(self._missing_evidence(finding))}</p></section>
      <section class="detail-box"><h4>Recommendation</h4><p>{self._escape(finding.recommendation)}</p></section>
      <section class="detail-box"><h4>Report context</h4><p><strong>Triage:</strong> {self._escape(triage)}<br><strong>CWE:</strong> {self._escape(self._cwe(finding))}<br><strong>CVSS:</strong> {self._escape(finding.cvss or "Not scored")}</p></section>
    </div>
    <details open><summary>Technical evidence</summary><pre class="evidence" id="{evidence_id}">{self._escape(finding.evidence)}</pre><button class="copy-button" type="button" data-copy-target="{evidence_id}">Copy evidence</button><p class="muted">Related HTTP request/response: {self._escape(self._http_context(finding))}</p></details>
    <details><summary>Investigation notes and references</summary><p>{self._escape(self._safe_investigation_path(finding))}</p><div class="reference-list">{references}</div><p class="muted">Suggested report template: scope, affected URL, observed behavior, sanitized evidence, impact demonstrated safely, and remediation recommendation.</p></details>
    <details><summary>Expandable technical details</summary>{details}</details>
  </div>
</details>"""

    def _finding_row(self, finding: Finding) -> str:
        severity = self._severity(finding)
        return f"""<tr data-severity="{severity}" data-title="{self._escape(finding.title).lower()}" data-module="{self._escape(finding.module).lower()}">
  <td><span class="badge" style="--severity-color:var(--{severity})">{self._escape(severity)}</span></td>
  <td>{self._escape(finding.title)}</td><td>{self._escape(finding.module)}</td><td>{self._escape(self._triage(finding))}</td><td>{self._escape(finding.evidence)}</td>
</tr>"""

    def _module_card(self, module: Any) -> str:
        icon = _MODULE_ICONS.get(module.module, "•")
        findings_count = len(module.findings)
        errors_count = len(module.errors)
        state = "Completed" if not errors_count else f"{errors_count} issue(s)"
        facts = self._data_facts(module.data)
        error_markup = (
            f'<details><summary>Module errors ({errors_count})</summary><pre class="evidence">'
            f"{self._escape(chr(10).join(module.errors))}</pre></details>"
            if errors_count
            else ""
        )
        return f"""<article class="card module">
  <div class="module-head"><span class="module-icon" aria-hidden="true">{self._escape(icon)}</span><h3 class="module-name">{self._escape(module.module)}</h3><span class="module-state">{self._escape(state)}</span></div>
  <p class="muted">{findings_count} finding(s) · {module.duration_ms} ms</p>
  <div class="facts">{facts}</div>{error_markup}
</article>"""

    def _data_facts(self, data: dict[str, Any]) -> str:
        if not data:
            return '<p class="muted">No structured data returned.</p>'
        rows = []
        for key, value in list(data.items())[:8]:
            rows.append(
                f'<div class="fact"><span class="fact-key">{self._escape(self._humanize(key))}</span>'
                f"<span>{self._value_summary(value)}</span></div>"
            )
        if len(data) > 8:
            rows.append(
                '<div class="fact"><span class="fact-key">Additional fields</span>'
                f"<span>{len(data) - 8} retained in the raw-data appendix.</span></div>"
            )
        return "".join(rows)

    def _value_summary(self, value: Any) -> str:
        if isinstance(value, list):
            if not value:
                return '<span class="muted">None</span>'
            chips = "".join(f'<span class="chip">{self._escape(item)}</span>' for item in value[:6])
            extra = f'<span class="chip">+{len(value) - 6} more</span>' if len(value) > 6 else ""
            return f'<span class="value-list">{chips}{extra}</span>'
        if isinstance(value, dict):
            return f'<span class="muted">{len(value)} structured field(s)</span>'
        if value in (None, ""):
            return '<span class="muted">Not observed</span>'
        return self._escape(value)

    def _module_bars(self, report: ScanReport) -> str:
        longest = max((module.duration_ms for module in report.modules), default=1)
        bars = []
        for module in report.modules:
            width = max(4, round((module.duration_ms / longest) * 100)) if longest else 4
            icon = self._escape(_MODULE_ICONS.get(module.module, "•"))
            bars.append(
                f'<div class="bar-row"><span class="bar-label"><span class="module-icon">{icon}</span>'
                f'{self._escape(module.module)}</span><span class="bar-track"><span class="bar-fill" '
                f'style="width:{width}%"></span></span><strong>{module.duration_ms} ms</strong></div>'
            )
        return "".join(bars) or '<p class="empty">No module timings are available.</p>'

    def _timeline(self, report: ScanReport) -> str:
        items = [
            f'<div class="timeline-item"><strong>Assessment started</strong><div class="timeline-time">{self._escape(report.started_at)}</div></div>'
        ]
        items.extend(
            f'<div class="timeline-item"><strong>{self._escape(module.module)}</strong><div class="timeline-time">Completed in {module.duration_ms} ms · {len(module.findings)} finding(s)</div></div>'
            for module in report.modules
        )
        items.append(
            f'<div class="timeline-item"><strong>Assessment finished</strong><div class="timeline-time">{self._escape(report.finished_at)}</div></div>'
        )
        return "".join(items)

    def _logo_markup(self) -> str:
        logo_url = self._safe_url(self.logo_url)
        if logo_url:
            return (
                '<span class="brand-mark"><img src="'
                f'{self._escape(logo_url)}" alt="{self._escape(self.brand_name)} logo" referrerpolicy="no-referrer"></span>'
            )
        return '<span class="brand-mark" aria-hidden="true">S</span>'

    @staticmethod
    def _safe_url(value: str) -> str:
        parsed = urlsplit(value)
        return value if parsed.scheme in {"http", "https"} and parsed.netloc else ""

    @staticmethod
    def _humanize(value: str) -> str:
        return value.replace("_", " ").strip().title()

    def _confidence(self, finding: Finding) -> str:
        title = finding.title.lower()
        if "possible" in title or "pattern" in finding.evidence.lower():
            return "Pattern-based / low"
        if finding.severity.value in {"high", "medium"}:
            return "Observed / requires validation"
        return "Observed / contextual"

    def _triage(self, finding: Finding) -> str:
        severity = self._severity(finding)
        if severity == "info":
            return "Informational"
        if severity == "low":
            return "Low Confidence"
        if severity == "medium":
            return "Needs Manual Investigation"
        if finding.cvss:
            return "Likely Reportable — validate impact"
        return "Potentially Reportable — validate impact"

    def _why_it_matters(self, finding: Finding) -> str:
        title = finding.title.lower()
        if "content-security-policy" in title or "header" in title:
            return "Defense-in-depth controls can reduce browser-side impact when another application flaw is present. Their absence alone is commonly informational in bug bounty programs."
        if "cors" in title:
            return "Overly broad cross-origin policy can expose data when combined with an authenticated browser session and an affected endpoint."
        if "cookie" in title:
            return "Cookie attributes influence whether browser sessions are protected during transport, script execution, and cross-site requests."
        if "secret" in title or "key" in title:
            return "A public client-side value may be sensitive, but it must be verified as live, scoped, and impactful before it is treated as a security issue."
        if "http" in title or "tls" in title or "certificate" in title:
            return "Transport configuration affects the confidentiality and integrity of users' connections, particularly when sensitive data is involved."
        return "The observation may indicate an exposed configuration or security control gap. Context, reachability, and practical impact still require manual confirmation."

    def _implications(self, finding: Finding) -> str:
        severity = self._severity(finding)
        if severity == "high":
            return "Potentially significant if the observation is reproducible, in scope, and shown to affect confidentiality, integrity, or availability without unsafe testing."
        if severity == "medium":
            return "May be relevant when combined with another confirmed weakness or business-sensitive behavior; do not infer exploitation from the scan alone."
        if severity == "low":
            return "Usually a hardening or contextual observation. Acceptance depends on the target's policy and demonstrated impact."
        return "Useful for understanding the target's security posture, but not normally reportable without additional evidence."

    def _verification_steps(self, finding: Finding) -> list[str]:
        return [
            "Confirm the exact URL and target are within the program's authorized scope.",
            "Repeat the observation manually at the configured rate without bypassing controls.",
            "Document the response metadata and realistic impact using sanitized evidence.",
            "Check program guidance and avoid reporting unless impact is confirmed and non-duplicate.",
        ]

    def _missing_evidence(self, finding: Finding) -> str:
        return (
            "Sentinel does not authenticate, exploit, or alter state. A manual reproduction, affected-user impact, "
            "and program-specific acceptance criteria have not been established."
        )

    def _safe_investigation_path(self, finding: Finding) -> str:
        return (
            "Follow the program's safe-harbor rules, validate only with non-destructive requests, and stop if "
            "verification would require authentication bypass, data access, or service disruption."
        )

    def _cwe(self, finding: Finding) -> str:
        title = finding.title.lower()
        if "cors" in title:
            return "CWE-942 (Permissive Cross-domain Policy)"
        if "cookie" in title:
            return "CWE-614 (Sensitive Cookie Without Secure Attribute)"
        if "header" in title or "content-security-policy" in title:
            return "CWE-693 (Protection Mechanism Failure)"
        if "http" in title or "tls" in title:
            return "CWE-319 (Cleartext Transmission of Sensitive Information)"
        if "secret" in title or "key" in title:
            return "CWE-798 (Use of Hard-coded Credentials) — unconfirmed"
        return "Not assigned"

    def _http_context(self, finding: Finding) -> str:
        if finding.url:
            return f"URL observed: {finding.url}. Full request/response bodies are intentionally not retained by this report."
        return "No full request/response pair was captured; use the finding evidence and module summary to reproduce safely."

    def _references(self, finding: Finding) -> str:
        title = finding.title.lower()
        links: list[tuple[str, str]] = [
            ("OWASP Testing Guide", "https://owasp.org/www-project-web-security-testing-guide/"),
        ]
        if "header" in title or "csp" in title:
            links.append(
                (
                    "OWASP HTTP Headers",
                    "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
                )
            )
        elif "cookie" in title:
            links.append(
                (
                    "OWASP Session Management",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
                )
            )
        elif "tls" in title or "http" in title or "certificate" in title:
            links.append(
                (
                    "OWASP TLS Guidance",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                )
            )
        elif "secret" in title or "key" in title:
            links.append(
                (
                    "OWASP Secrets Management",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
                )
            )
        return "".join(
            f'<a href="{href}" target="_blank" rel="noreferrer">{self._escape(label)}</a>'
            for label, href in links
        )

    def _technical_details(self, finding: Finding) -> str:
        rows = [
            ("Module", finding.module),
            ("Severity", self._severity(finding)),
            ("Confidence", self._confidence(finding)),
            ("URL", finding.url or "Not captured"),
            ("CVSS", finding.cvss or "Not scored"),
        ]
        return "".join(
            f'<div class="fact"><span class="fact-key">{self._escape(key)}</span><span>{self._escape(value)}</span></div>'
            for key, value in rows
        )

    @staticmethod
    def _list_items(items: list[str]) -> str:
        return "".join(f"<li>{html.escape(item)}</li>" for item in items)

    @staticmethod
    def _json_for_html(data: dict[str, Any]) -> str:
        return json.dumps(data, default=str).replace("</", "<\\/")

    def to_csv(self, report: ScanReport) -> str:
        """Render one row per finding for spreadsheet workflows."""
        output = StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "severity",
                "title",
                "description",
                "evidence",
                "recommendation",
                "module",
                "cvss",
                "url",
            ],
        )
        writer.writeheader()
        for finding in self.findings(report):
            writer.writerow(
                {
                    "severity": finding.severity,
                    "title": finding.title,
                    "description": finding.description,
                    "evidence": finding.evidence,
                    "recommendation": finding.recommendation,
                    "module": finding.module,
                    "cvss": finding.cvss,
                    "url": finding.url,
                }
            )
        return output.getvalue()

    def to_pdf(self, report: ScanReport, output: Path) -> None:
        """Render a compact PDF using ReportLab when the optional runtime is installed."""
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen.canvas import Canvas

        canvas = Canvas(str(output), pagesize=A4)
        width, height = A4
        x, y = 48, height - 48

        def line(value: str, bold: bool = False) -> None:
            nonlocal y
            if y < 60:
                canvas.showPage()
                y = height - 48
            canvas.setFont("Helvetica-Bold" if bold else "Helvetica", 10 if bold else 9)
            canvas.drawString(x, y, value[:150])
            y -= 15

        line("Sentinel assessment report", bold=True)
        line(f"Target: {report.target}")
        line(f"Started: {report.started_at}")
        line(report.notice)
        line("Findings", bold=True)
        findings = self.findings(report)
        if not findings:
            line("No reportable observations were produced.")
        for finding in findings:
            line(f"[{finding.severity.upper()}] {finding.title}", bold=True)
            for item in wrap(finding.description, width=105):
                line(item)
            for item in wrap(f"Evidence: {finding.evidence}", width=105):
                line(item)
            for item in wrap(f"Recommendation: {finding.recommendation}", width=105):
                line(item)
        canvas.save()
