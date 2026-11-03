"""网络地址工具：内网/保留地址判定与 IOC 降噪。"""

from __future__ import annotations

import ipaddress

from app.core.config import settings

# 常见良性域名（避免把系统/公共基础设施误判为 C2）
BENIGN_DOMAINS = {
    "microsoft.com", "windows.com", "windowsupdate.com", "msftncsi.com", "msftconnecttest.com",
    "verisign.com", "digicert.com", "globalsign.com", "sectigo.com", "letsencrypt.org",
    "w3.org", "apache.org", "google.com", "gstatic.com", "googleapis.com",
    "cloudflare.com", "akamai.net", "akamaiedge.net", "bing.com", "live.com",
    "adobe.com", "oracle.com", "java.com", "apple.com", "mozilla.org",
}


def _nets():
    return [ipaddress.ip_network(n) for n in settings.PRIVATE_NETS]


_PRIVATE_NETS = None


def is_private_ip(value: str) -> bool:
    """判断是否为内网/保留地址。"""
    global _PRIVATE_NETS
    if _PRIVATE_NETS is None:
        _PRIVATE_NETS = _nets()
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_link_local or ip.is_reserved:
        return True
    return any(ip in net for net in _PRIVATE_NETS)


def is_benign_domain(domain: str) -> bool:
    """判断域名是否属于已知良性基础设施。"""
    domain = domain.lower().strip().rstrip(".")
    return any(domain == d or domain.endswith("." + d) for d in BENIGN_DOMAINS)


def is_valid_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False
