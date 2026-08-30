"""Passive SPF and DMARC policy checks using only the target's DNS records."""

from __future__ import annotations

import dns.asyncresolver
import dns.resolver

from sentinel.models import Finding, ModuleResult, Severity
from sentinel.modules.base import ScanContext, ScanModule


class EmailSecurityModule(ScanModule):
    """Summarize published email-authentication policies without sending mail.

    SPF and DMARC records are deliberately published in DNS for anyone to read;
    inspecting them is passive with respect to the target. No email is sent and
    no mail server is contacted.
    """

    name = "email_security"
    _MAX_DOMAIN_CANDIDATES = 3

    async def run(self, context: ScanContext) -> ModuleResult:
        if not context.config.enable_email_security:
            return ModuleResult(
                module=self.name,
                data={"enabled": False, "reason": "Email-security DNS checks are disabled."},
            )
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = context.config.timeout_seconds
        candidates = self._domain_candidates(context.target.host)
        spf_records: list[str] = []
        dmarc_record = ""
        errors: list[str] = []
        for domain in candidates:
            try:
                answer = await resolver.resolve(domain, "TXT", raise_on_no_answer=False)
                for item in answer:
                    text = item.to_text().strip('"')
                    if text.lower().startswith("v=spf1") and not spf_records:
                        spf_records = [text]
            except Exception as exc:
                errors.append(f"SPF {domain}: {type(exc).__name__}: {exc}")
        for domain in candidates:
            try:
                answer = await resolver.resolve(f"_dmarc.{domain}", "TXT", raise_on_no_answer=False)
                for item in answer:
                    text = item.to_text().strip('"')
                    if text.lower().startswith("v=dmarc1"):
                        dmarc_record = text
                        break
            except Exception as exc:
                errors.append(f"DMARC {domain}: {type(exc).__name__}: {exc}")
            if dmarc_record:
                break

        findings = self._findings(context.target.url, spf_records, dmarc_record)
        return ModuleResult(
            module=self.name,
            data={
                "enabled": True,
                "checked_domains": candidates,
                "spf_records": spf_records,
                "dmarc_record": dmarc_record,
                "dmarc_policy": self._dmarc_policy(dmarc_record),
                "note": (
                    "Policy metadata read from public DNS only. Sentinel never sends email "
                    "and does not verify mail-server behavior."
                ),
            },
            findings=findings,
            errors=errors,
        )

    @classmethod
    def _domain_candidates(cls, host: str) -> list[str]:
        """Return the host and its parent domains that could publish email policy."""
        labels = host.rstrip(".").split(".")
        if len(labels) == 1:
            return [host]
        candidates = [".".join(labels[index:]) for index in range(len(labels) - 1)]
        return list(dict.fromkeys(candidates))[: cls._MAX_DOMAIN_CANDIDATES]

    @staticmethod
    def _dmarc_policy(record: str) -> str:
        lowered = record.lower()
        for marker in ("p=none", "p=quarantine", "p=reject"):
            if marker in lowered:
                return marker.split("=", 1)[1]
        return "unknown"

    @staticmethod
    def _findings(url: str, spf_records: list[str], dmarc_record: str) -> list[Finding]:
        findings: list[Finding] = []
        if not spf_records:
            findings.append(
                Finding(
                    title="Domain has no published SPF policy",
                    severity=Severity.LOW,
                    description=(
                        "No SPF TXT record was observed for the checked domains. Missing SPF "
                        "makes it easier for attackers to forge envelope senders."
                    ),
                    evidence="No 'v=spf1' TXT record returned by the target's DNS.",
                    recommendation=(
                        "Publish an SPF policy that ends with '-all' (or a reviewed '~all') "
                        "and covers only authorized mail senders."
                    ),
                    module=EmailSecurityModule.name,
                    url=url,
                )
            )
        else:
            policy = " ".join(spf_records).lower()
            if "+all" in policy:
                findings.append(
                    Finding(
                        title="SPF policy permits any host to send mail",
                        severity=Severity.MEDIUM,
                        description=(
                            "The published SPF record ends with '+all', which authorizes every "
                            "host on the internet to send mail for the domain."
                        ),
                        evidence=spf_records[0],
                        recommendation=(
                            "Restrict the SPF mechanism list to legitimate senders and end the "
                            "policy with '-all' or a reviewed '~all'."
                        ),
                        module=EmailSecurityModule.name,
                        url=url,
                    )
                )
        if not dmarc_record:
            findings.append(
                Finding(
                    title="Domain has no published DMARC policy",
                    severity=Severity.LOW,
                    description=(
                        "No DMARC TXT record was observed at the checked _dmarc names. Missing "
                        "DMARC removes domain-level policy and reporting for email spoofing."
                    ),
                    evidence="No 'v=DMARC1' TXT record returned by the target's DNS.",
                    recommendation=(
                        "Publish a DMARC record starting with 'p=none' for monitoring, then "
                        "move to quarantine/reject once legitimate mail passes."
                    ),
                    module=EmailSecurityModule.name,
                    url=url,
                )
            )
        elif "p=none" in dmarc_record.lower():
            findings.append(
                Finding(
                    title="DMARC policy is in monitor-only mode",
                    severity=Severity.INFO,
                    description=(
                        "A DMARC record exists but only requests monitoring (p=none); it does "
                        "not instruct receivers to quarantine or reject spoofed mail."
                    ),
                    evidence=dmarc_record,
                    recommendation=(
                        "Analyze DMARC reports, align SPF/DKIM, then strengthen the policy to "
                        "quarantine or reject."
                    ),
                    module=EmailSecurityModule.name,
                    url=url,
                )
            )
        return findings
