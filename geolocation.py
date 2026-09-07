"""
IP geolocation — approximate infrastructure location only.
Offline fallback table so the demo works without an internet call / API key;
set use_live_api=True with an ipinfo.io token for real lookups in production.
"""

try:
    import requests
except ImportError:
    requests = None

_OFFLINE_GEO_SAMPLE = {
    "203.0.113.5": {"city": "Frankfurt", "country": "DE", "lat": 50.1109, "lng": 8.6821, "org": "Example Cloud Hosting", "asn": "AS64500"},
    "198.51.100.23": {"city": "Ashburn", "country": "US", "lat": 39.0438, "lng": -77.4874, "org": "Example Data Center", "asn": "AS64501"},
    "192.0.2.77": {"city": "Mumbai", "country": "IN", "lat": 19.0760, "lng": 72.8777, "org": "Example ISP India", "asn": "AS64502"},
}


def _is_private_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or a == 127


def geolocate_ip(ip: str, use_live_api: bool = False, api_token: str = "") -> dict:
    if _is_private_ip(ip):
        return {
            "ip": ip, "city": "Private/Internal", "country": "-",
            "lat": None, "lng": None, "org": "Internal network", "asn": "-",
            "note": "Private IP address — no public geolocation available.",
        }

    if use_live_api and requests is not None:
        try:
            url = f"https://ipinfo.io/{ip}/json"
            if api_token:
                url += f"?token={api_token}"
            resp = requests.get(url, timeout=3)
            if resp.ok:
                d = resp.json()
                loc = d.get("loc", ",").split(",")
                lat = float(loc[0]) if loc[0] else None
                lng = float(loc[1]) if len(loc) > 1 and loc[1] else None
                return {
                    "ip": ip, "city": d.get("city", "Unknown"), "country": d.get("country", "Unknown"),
                    "lat": lat, "lng": lng, "org": d.get("org", "Unknown"), "asn": d.get("org", "-").split()[0] if d.get("org") else "-",
                    "note": "Approximate infrastructure location — not proof of physical attacker location.",
                }
        except Exception:
            pass

    fallback = _OFFLINE_GEO_SAMPLE.get(ip, {
        "city": "Unresolved (offline demo mode)", "country": "-",
        "lat": None, "lng": None, "org": "Unknown — enable live API for real lookup", "asn": "-",
    })
    return {
        "ip": ip,
        **fallback,
        "note": "Approximate infrastructure location — VPNs, proxies, and compromised "
                "hosts can mislead attribution. This is not proof of physical location.",
    }
