from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import networkx as nx

if TYPE_CHECKING:
    from app.services.domain_intel import DomainIntel


@dataclass
class CorrelationResult:
    graph_nodes: list[dict] = field(default_factory=list)
    graph_edges: list[dict] = field(default_factory=list)
    linked_domains: list[str] = field(default_factory=list)
    linked_ips: list[str] = field(default_factory=list)
    campaign_clusters: list[dict] = field(default_factory=list)
    attribution_confidence: float = 0.0
    threat_actors: list[dict] = field(default_factory=list)


class GraphCorrelator:
    """Build a relationship graph linking domains, IPs, ISPs, and threat campaigns."""

    def __init__(self):
        self.graph = nx.DiGraph()

    def correlate(
        self,
        parsed_email,
        header_analysis,
        geo_result,
        domain_intel,
    ) -> CorrelationResult:
        result = CorrelationResult()

        sender_domain = header_analysis.sender_domain
        earliest_ip = header_analysis.earliest_reliable_ip

        self.graph.add_node(
            sender_domain,
            type="domain",
            label=sender_domain,
            suspicious=domain_intel.is_suspicious,
        )
        if earliest_ip:
            self.graph.add_node(
                earliest_ip,
                type="ip",
                label=earliest_ip,
                country=geo_result.country,
                isp=geo_result.isp,
                is_vpn=geo_result.is_vpn,
                is_tor=geo_result.is_tor,
            )
            self.graph.add_edge(
                earliest_ip,
                sender_domain,
                relationship="sends_from",
            )

        if geo_result.isp:
            isp_node = f"ISP: {geo_result.isp}"
            self.graph.add_node(isp_node, type="isp", label=geo_result.isp)
            if earliest_ip:
                self.graph.add_edge(earliest_ip, isp_node, relationship="uses_isp")

        for hop in header_analysis.relay_path:
            if "ip" in hop:
                hop_ip = hop["ip"]
                self.graph.add_node(
                    hop_ip, type="relay", label=hop_ip
                )
                if "from_host" in hop:
                    relay_host = hop["from_host"]
                    self.graph.add_node(
                        relay_host, type="relay_host", label=relay_host
                    )
                    self.graph.add_edge(
                        relay_host, hop_ip, relationship="resolves_to"
                    )

        if parsed_email.reply_to:
            reply_domain = GraphCorrelator._extract_domain(parsed_email.reply_to)
            if reply_domain and reply_domain != sender_domain:
                self.graph.add_node(
                    reply_domain, type="domain", label=reply_domain, suspicious=True
                )
                self.graph.add_edge(
                    sender_domain,
                    reply_domain,
                    relationship="reply_to_mismatch",
                )
                result.linked_domains.append(reply_domain)

        if domain_intel.a_records:
            for a_ip in domain_intel.a_records:
                self.graph.add_node(a_ip, type="ip", label=a_ip)
                self.graph.add_edge(
                    a_ip, sender_domain, relationship="resolves_to"
                )
                result.linked_ips.append(a_ip)

        for ns in domain_intel.name_servers:
            self.graph.add_node(ns, type="nameserver", label=ns)
            self.graph.add_edge(
                sender_domain, ns, relationship="uses_nameserver"
            )

        result.graph_nodes = [
            {
                "id": node,
                "type": self.graph.nodes[node].get("type", "unknown"),
                "label": self.graph.nodes[node].get("label", node),
                **{k: v for k, v in self.graph.nodes[node].items()
                   if k not in ("type", "label")},
            }
            for node in self.graph.nodes
        ]
        result.graph_edges = [
            {
                "source": u,
                "target": v,
                "relationship": self.graph.edges[u, v].get("relationship", ""),
            }
            for u, v in self.graph.edges
        ]

        result.linked_domains = list(set(result.linked_domains))
        result.linked_ips = list(set(result.linked_ips))

        result.attribution_confidence = self._compute_attribution_confidence(
            domain_intel, geo_result, header_analysis
        )

        result.campaign_clusters = self._detect_campaigns()

        return result

    def _compute_attribution_confidence(
        self, domain_intel, geo_result, header_analysis
    ) -> float:
        confidence = 0.0

        if domain_intel.is_suspicious:
            confidence += 0.2
        if geo_result.is_vpn or geo_result.is_tor:
            confidence += 0.15
        if header_analysis.earliest_reliable_ip:
            confidence += 0.2
        if domain_intel.domain_age_days > 0 and domain_intel.domain_age_days < 30:
            confidence += 0.15
        if header_analysis.reply_to_mismatch:
            confidence += 0.1
        anomaly_factor = min(len(header_analysis.anomalies) * 0.05, 0.2)
        confidence += anomaly_factor

        return min(confidence, 1.0)

    def _detect_campaigns(self) -> list[dict]:
        clusters = []
        try:
            undirected = self.graph.to_undirected()
            for component in nx.connected_components(undirected):
                if len(component) > 2:
                    nodes = list(component)
                    suspicious_count = sum(
                        1
                        for n in nodes
                        if self.graph.nodes[n].get("suspicious", False)
                    )
                    clusters.append(
                        {
                            "nodes": nodes,
                            "size": len(nodes),
                            "suspicious_ratio": suspicious_count / len(nodes),
                        }
                    )
        except Exception:
            pass
        return clusters

    @staticmethod
    def _extract_domain(addr: str) -> str:
        import re
        match = re.search(r"@([\w.-]+)", addr)
        return match.group(1) if match else ""
