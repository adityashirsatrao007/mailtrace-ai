from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class GeoResult:
    ip: str = ""
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    isp: str = ""
    org: str = ""
    as_number: str = ""
    is_vpn: bool = False
    is_tor: bool = False
    is_proxy: bool = False
    hosting_provider: str = ""
    reverse_dns: str = ""


class GeoLocator:
    """Resolve IP addresses to geolocation and infrastructure intel."""

    VPN_INDICATORS = [
        "vpn", "tunnel", "proxy", "anonymiz", "nordvpn", "expressvpn",
        "surfshark", "protonvpn", "windscribe", "hidemy", "tor",
    ]

    HOSTING_INDICATORS = [
        "amazon", "aws", "google cloud", "azure", "digitalocean",
        "linode", "vultr", "ovh", "hetzner", "cloudflare",
    ]

    @staticmethod
    async def locate(ip: str) -> GeoResult:
        import httpx

        result = GeoResult(ip=ip)

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"http://ip-api.com/json/{ip}")
                if resp.status_code == 200:
                    data = resp.json()
                    result.country = data.get("country", "")
                    result.country_code = data.get("countryCode", "")
                    result.region = data.get("regionName", "")
                    result.city = data.get("city", "")
                    result.latitude = data.get("lat", 0.0)
                    result.longitude = data.get("lon", 0.0)
                    result.isp = data.get("isp", "")
                    result.org = data.get("org", "")
                    result.as_number = data.get("as", "")
                    result.hosting_provider = data.get("org", "")
        except Exception:
            pass

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"https://dns.google/resolve?name={ip}&type=PTR")
                if resp.status_code == 200:
                    data = resp.json()
                    answers = data.get("Answer", [])
                    if answers:
                        result.reverse_dns = answers[0].get("data", "")
        except Exception:
            pass

        result.is_vpn = GeoLocator._check_vpn(result)
        result.is_tor = await GeoLocator._check_tor(ip)
        result.is_proxy = result.is_vpn or result.is_tor

        return result

    @staticmethod
    def _check_vpn(result: GeoResult) -> bool:
        combined = f"{result.isp} {result.org} {result.reverse_dns}".lower()
        return any(ind in combined for ind in GeoLocator.VPN_INDICATORS)

    @staticmethod
    async def _check_tor(ip: str) -> bool:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(
                    "https://check.torproject.org/torbulkexitlist"
                )
                if resp.status_code == 200:
                    return ip in resp.text
        except Exception:
            pass
        return False

    @staticmethod
    async def locate_batch(ips: list[str]) -> list[GeoResult]:
        results = []
        for ip in ips:
            result = await GeoLocator.locate(ip)
            results.append(result)
        return results
