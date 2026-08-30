"""Build a deterministic local knowledge graph from existing Sentinel scan data."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit


@dataclass(frozen=True, slots=True)
class GraphNode:
    """One asset or observation represented in the local knowledge graph."""

    node_id: str
    kind: str
    label: str
    properties: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-friendly node."""
        return {
            "id": self.node_id,
            "kind": self.kind,
            "label": self.label,
            "properties": self.properties,
        }


@dataclass(frozen=True, slots=True)
class GraphEdge:
    """A typed relationship between two graph nodes."""

    source: str
    target: str
    relationship: str

    def as_dict(self) -> dict[str, str]:
        """Return a JSON-friendly relationship."""
        return {"source": self.source, "target": self.target, "relationship": self.relationship}


@dataclass(slots=True)
class KnowledgeGraph:
    """A deduplicated graph suitable for a future local interactive viewer."""

    target: str
    scan_id: int | None = None
    _nodes: dict[str, GraphNode] = field(default_factory=dict)
    _edges: set[GraphEdge] = field(default_factory=set)

    def add_node(self, kind: str, label: str, properties: dict[str, str] | None = None) -> str:
        """Add or reuse a stable node and return its identifier."""
        clean_label = label.strip()
        if not clean_label:
            raise ValueError("Knowledge-graph nodes require a non-empty label.")
        node_id = _node_id(kind, clean_label)
        if node_id not in self._nodes:
            self._nodes[node_id] = GraphNode(
                node_id=node_id,
                kind=kind,
                label=clean_label,
                properties=dict(properties or {}),
            )
        return node_id

    def add_edge(self, source: str, target: str, relationship: str) -> None:
        """Connect two known graph nodes with a descriptive relationship."""
        if source not in self._nodes or target not in self._nodes:
            raise ValueError("Knowledge-graph edges must reference existing nodes.")
        self._edges.add(GraphEdge(source=source, target=target, relationship=relationship))

    def as_dict(self) -> dict[str, object]:
        """Return stable, visualization-neutral graph data."""
        nodes = sorted(self._nodes.values(), key=lambda node: (node.kind, node.label.lower()))
        edges = sorted(
            self._edges,
            key=lambda edge: (edge.relationship, edge.source, edge.target),
        )
        return {
            "target": self.target,
            "scan_id": self.scan_id,
            "nodes": [node.as_dict() for node in nodes],
            "edges": [edge.as_dict() for edge in edges],
            "statistics": {"nodes": len(nodes), "edges": len(edges)},
            "notice": (
                "This graph is derived only from stored, non-destructive Sentinel observations. "
                "It is an investigation aid, not evidence of exploitation or ownership."
            ),
        }


def build_knowledge_graph(report: dict[str, Any], scan_id: int | None = None) -> KnowledgeGraph:
    """Map a serialized Sentinel report into domains, assets, metadata, and observations."""
    target = str(report.get("target", ""))
    if not target:
        raise ValueError("A stored scan must contain a target before a graph can be built.")
    parsed_target = urlsplit(target)
    host = parsed_target.hostname or target
    graph = KnowledgeGraph(target=target, scan_id=scan_id)
    domain_node = graph.add_node("domain", host, {"source": "scan target"})
    target_node = graph.add_node("application", target, {"scheme": parsed_target.scheme})
    graph.add_edge(domain_node, target_node, "hosts")
    modules = _module_data(report)

    _add_subdomains(graph, domain_node, modules.get("recon", {}))
    _add_dns(graph, domain_node, modules.get("dns", {}))
    _add_technology(graph, target_node, modules.get("technology", {}))
    _add_tls(graph, target_node, modules.get("tls", {}))
    _add_http(graph, target_node, modules.get("http", {}), modules.get("headers", {}))
    _add_ports(graph, domain_node, modules.get("ports", {}))
    _add_web_assets(
        graph,
        target_node,
        modules.get("javascript", {}),
        modules.get("api_discovery", {}),
        modules.get("surface", {}),
        modules.get("robots", {}),
        modules.get("sitemap", {}),
        modules.get("crawler", {}),
    )
    _add_scope(graph, target_node, modules.get("scope", {}))
    _add_public_artifacts(graph, target_node, modules.get("public_artifacts", {}))
    _add_observations(graph, target_node, report)
    return graph


def _module_data(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    modules = report.get("modules", [])
    if not isinstance(modules, list):
        return {}
    return {
        str(module.get("module", "unknown")): data
        for module in modules
        if isinstance(module, dict) and isinstance((data := module.get("data", {})), dict)
    }


def _add_subdomains(graph: KnowledgeGraph, domain_node: str, data: dict[str, Any]) -> None:
    for subdomain in _strings(data.get("passive_subdomains")):
        child = graph.add_node(
            "subdomain", subdomain, {"source": "passive certificate transparency"}
        )
        graph.add_edge(child, domain_node, "subdomain_of")
    for provider in _strings(data.get("cdn")):
        node = graph.add_node("cdn", provider)
        graph.add_edge(node, domain_node, "fronts")
    for provider in _strings(data.get("waf")):
        node = graph.add_node("waf_hint", provider)
        graph.add_edge(node, domain_node, "protects_hint")


def _add_dns(graph: KnowledgeGraph, domain_node: str, data: dict[str, Any]) -> None:
    records = data.get("records", {})
    if not isinstance(records, dict):
        return
    for record_type, values in records.items():
        for value in _strings(values):
            node = graph.add_node("dns_record", value, {"record_type": str(record_type)})
            graph.add_edge(domain_node, node, "resolves_to")


def _add_technology(graph: KnowledgeGraph, target_node: str, data: dict[str, Any]) -> None:
    for technology in _strings(data.get("technologies")):
        node = graph.add_node("technology", technology)
        graph.add_edge(target_node, node, "uses")
    hints = data.get("technology_hints", {})
    if not isinstance(hints, dict):
        return
    for category, values in hints.items():
        for value in _strings(values):
            node = graph.add_node("technology_hint", value, {"category": str(category)})
            graph.add_edge(target_node, node, "exposes_hint")


def _add_tls(graph: KnowledgeGraph, target_node: str, data: dict[str, Any]) -> None:
    if not bool(data.get("applicable")):
        return
    subject = str(data.get("certificate_subject", "TLS certificate"))
    properties = {
        "issuer": str(data.get("certificate_issuer", "")),
        "not_after": str(data.get("certificate_not_after", "")),
        "tls_version": str(data.get("tls_version", "")),
    }
    certificate = graph.add_node("certificate", subject, properties)
    graph.add_edge(target_node, certificate, "presents")


def _add_http(
    graph: KnowledgeGraph,
    target_node: str,
    http_data: dict[str, Any],
    header_data: dict[str, Any],
) -> None:
    for cookie in _strings(http_data.get("cookie_names")):
        node = graph.add_node("cookie", cookie)
        graph.add_edge(target_node, node, "sets")
    observed = header_data.get("observed_headers", {})
    if not isinstance(observed, dict):
        return
    for name, value in observed.items():
        if value:
            node = graph.add_node("header", str(name), {"value": str(value)})
            graph.add_edge(target_node, node, "returns")


def _add_ports(graph: KnowledgeGraph, domain_node: str, data: dict[str, Any]) -> None:
    ports = data.get("open_ports", [])
    if not isinstance(ports, list):
        return
    for entry in ports:
        if not isinstance(entry, dict):
            continue
        port = str(entry.get("port", "unknown"))
        service = str(entry.get("service", "unknown"))
        node = graph.add_node("network_service", f"{service}:{port}", {"port": port})
        graph.add_edge(domain_node, node, "exposes")


def _add_web_assets(
    graph: KnowledgeGraph,
    target_node: str,
    javascript: dict[str, Any],
    api: dict[str, Any],
    surface: dict[str, Any],
    robots: dict[str, Any],
    sitemap: dict[str, Any],
    crawler: dict[str, Any],
) -> None:
    for source in _strings(javascript.get("script_sources")):
        node = graph.add_node("javascript", source)
        graph.add_edge(target_node, node, "loads")
    endpoints = set(_strings(javascript.get("endpoint_candidates")))
    endpoints.update(_strings(api.get("public_endpoint_candidates")))
    endpoints.update(_strings(surface.get("graphql_candidates")))
    for endpoint in sorted(endpoints):
        kind = "graphql_endpoint" if "graphql" in endpoint.lower() else "api_endpoint"
        node = graph.add_node(kind, endpoint)
        graph.add_edge(target_node, node, "references")
    for endpoint in _strings(surface.get("websocket_candidates")):
        node = graph.add_node("websocket_endpoint", endpoint)
        graph.add_edge(target_node, node, "references")
    for auth_point in _strings(surface.get("authentication_points")):
        node = graph.add_node("authentication_point", auth_point)
        graph.add_edge(target_node, node, "exposes")
    forms = surface.get("forms", [])
    if isinstance(forms, list):
        for form in forms:
            if not isinstance(form, dict):
                continue
            action = str(form.get("action", ""))
            if not action:
                continue
            node = graph.add_node(
                "form",
                action,
                {
                    "method": str(form.get("method", "")),
                    "has_password": str(bool(form.get("has_password", False))),
                    "same_origin": str(bool(form.get("same_origin", False))),
                },
            )
            graph.add_edge(target_node, node, "contains")
    for path in _strings(robots.get("disallowed_paths")):
        node = graph.add_node("published_path", path, {"source": "robots.txt"})
        graph.add_edge(target_node, node, "publishes")
    for url in _strings(sitemap.get("urls")):
        node = graph.add_node("published_url", url, {"source": "sitemap"})
        graph.add_edge(target_node, node, "publishes")
    crawled_pages = crawler.get("pages", [])
    if isinstance(crawled_pages, list):
        for page in crawled_pages:
            if not isinstance(page, dict):
                continue
            url = str(page.get("url", ""))
            if not url:
                continue
            node = graph.add_node(
                "crawled_url",
                url,
                {
                    "depth": str(page.get("depth", "")),
                    "status_code": str(page.get("status_code", "")),
                },
            )
            graph.add_edge(target_node, node, "requested")


def _add_scope(graph: KnowledgeGraph, target_node: str, data: dict[str, Any]) -> None:
    name = str(data.get("name", ""))
    if not name:
        return
    node = graph.add_node(
        "assessment_scope",
        name,
        {"rate_limit_per_second": str(data.get("rate_limit_per_second", ""))},
    )
    graph.add_edge(target_node, node, "assessed_under")


def _add_public_artifacts(graph: KnowledgeGraph, target_node: str, data: dict[str, Any]) -> None:
    artifacts = data.get("public_artifacts", {})
    if not isinstance(artifacts, dict):
        return
    for artifact_name, artifact in artifacts.items():
        if not isinstance(artifact, dict):
            continue
        url = str(artifact.get("url", artifact_name))
        properties = {"status_code": str(artifact.get("status_code", ""))}
        if artifact_name == "favicon":
            properties["sha256"] = str(artifact.get("sha256", ""))
        node = graph.add_node("public_artifact", url, properties)
        graph.add_edge(target_node, node, "publishes")


def _add_observations(graph: KnowledgeGraph, target_node: str, report: dict[str, Any]) -> None:
    modules = report.get("modules", [])
    if not isinstance(modules, list):
        return
    for module in modules:
        if not isinstance(module, dict):
            continue
        module_name = str(module.get("module", "unknown"))
        findings = module.get("findings", [])
        if not isinstance(findings, list):
            continue
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            title = str(finding.get("title", "Untitled observation"))
            node = graph.add_node(
                "observation",
                title,
                {
                    "module": str(finding.get("module", module_name)),
                    "severity": str(finding.get("severity", "info")),
                    "url": str(finding.get("url", "")),
                },
            )
            graph.add_edge(target_node, node, "has_observation")


def _strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


def _node_id(kind: str, label: str) -> str:
    digest = hashlib.sha256(f"{kind}\x00{label}".encode()).hexdigest()[:16]
    return f"{kind}:{digest}"
