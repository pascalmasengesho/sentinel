"""TLS handshake and certificate metadata collection without cipher enumeration."""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import AuthorityInformationAccessOID

from sentinel.models import Finding, ModuleResult, Severity
from sentinel.modules.base import ScanContext, ScanModule


class TlsModule(ScanModule):
    """Record the normal negotiated TLS configuration for an HTTPS target."""

    name = "tls"

    async def run(self, context: ScanContext) -> ModuleResult:
        if context.target.scheme != "https":
            return ModuleResult(
                module=self.name, data={"applicable": False, "reason": "Target uses HTTP."}
            )
        port = context.target.port or 443
        details = await asyncio.to_thread(
            self._inspect, context.target.host, port, context.config.timeout_seconds
        )
        findings: list[Finding] = []
        days_remaining = details.get("days_remaining")
        if isinstance(days_remaining, int) and days_remaining < 15:
            findings.append(
                Finding(
                    title="TLS certificate expires soon",
                    severity=Severity.MEDIUM if days_remaining < 0 else Severity.LOW,
                    description="The presented certificate is near expiry or has expired.",
                    evidence=f"Certificate has {days_remaining} day(s) remaining.",
                    recommendation="Renew and deploy a valid certificate before expiration.",
                    module=self.name,
                    url=context.target.url,
                )
            )
        return ModuleResult(module=self.name, data=details, findings=findings)

    @staticmethod
    def _inspect(host: str, port: int, timeout: float) -> dict[str, Any]:
        ssl_context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as tcp_socket:
            with ssl_context.wrap_socket(tcp_socket, server_hostname=host) as tls_socket:
                certificate_der = tls_socket.getpeercert(binary_form=True)
                if certificate_der is None:
                    raise ssl.SSLError("The TLS peer did not present a certificate.")
                certificate = x509.load_der_x509_certificate(certificate_der, default_backend())
                expires_at = certificate.not_valid_after_utc
                now = datetime.now(UTC)
                ocsp_urls: list[str] = []
                try:
                    aia = certificate.extensions.get_extension_for_class(
                        x509.AuthorityInformationAccess
                    ).value
                    ocsp_urls = [
                        access.access_location.value
                        for access in aia
                        if access.access_method == AuthorityInformationAccessOID.OCSP
                    ]
                except x509.ExtensionNotFound:
                    pass
                cipher = tls_socket.cipher()
                return {
                    "applicable": True,
                    "tls_version": tls_socket.version(),
                    "negotiated_cipher": cipher[0] if cipher else "",
                    "cipher_protocol": cipher[1] if cipher else "",
                    "certificate_subject": certificate.subject.rfc4514_string(),
                    "certificate_issuer": certificate.issuer.rfc4514_string(),
                    "certificate_not_after": expires_at.isoformat(),
                    "days_remaining": (expires_at - now).days,
                    "certificate_chain": (
                        "The standard-library handshake exposes the leaf certificate only."
                    ),
                    "ocsp_responder_urls": ocsp_urls,
                    "note": (
                        "This observes the normal handshake; it does not enumerate ciphers "
                        "or force legacy TLS versions."
                    ),
                }
