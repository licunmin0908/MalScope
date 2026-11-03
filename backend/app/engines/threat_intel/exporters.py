"""IOC 导出：CSV / JSON / STIX 2.1 / OpenIOC。

输入为 IOC 字典列表（或带同名属性的 ORM 对象），输出为字符串或字节。
STIX/OpenIOC 便于与 MISP、OpenCTI 等威胁情报平台对接。
"""

from __future__ import annotations

import csv
import datetime as dt
import io
import json
import uuid
import xml.etree.ElementTree as ET


def _get(ioc, key, default=None):
    if isinstance(ioc, dict):
        return ioc.get(key, default)
    return getattr(ioc, key, default)


def to_json(iocs: list) -> str:
    rows = [
        {
            "type": _get(i, "ioc_type"),
            "value": _get(i, "value"),
            "source": _get(i, "source"),
            "context": _get(i, "context"),
            "confidence": _get(i, "confidence"),
            "threat_score": _get(i, "threat_score"),
            "tags": _get(i, "tags") or [],
        }
        for i in iocs
    ]
    return json.dumps(rows, ensure_ascii=False, indent=2)


def to_csv(iocs: list) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["type", "value", "source", "confidence", "threat_score", "context", "tags"])
    for i in iocs:
        writer.writerow([
            _get(i, "ioc_type"), _get(i, "value"), _get(i, "source"),
            _get(i, "confidence"), _get(i, "threat_score"), _get(i, "context"),
            ";".join(_get(i, "tags") or []),
        ])
    return buf.getvalue()


def to_stix(iocs: list) -> str:
    """生成 STIX 2.1 Bundle。"""
    try:
        import stix2
    except ImportError:  # pragma: no cover
        return json.dumps({"error": "未安装 stix2 库"}, ensure_ascii=False)

    now = dt.datetime.now(dt.timezone.utc)
    objects = []
    for i in iocs:
        ioc_type = _get(i, "ioc_type")
        value = _get(i, "value")
        pattern = _stix_pattern(ioc_type, value)
        if not pattern:
            continue
        objects.append(
            stix2.Indicator(
                name=f"{ioc_type}: {value[:80]}",
                description=_get(i, "context") or "",
                pattern=pattern,
                pattern_type="stix",
                valid_from=now,
                confidence=min(_get(i, "confidence", 50) or 50, 100),
                labels=["malicious-activity"],
            )
        )
    bundle = stix2.Bundle(objects=objects, allow_custom=True)
    return bundle.serialize(pretty=True)


def _stix_pattern(ioc_type: str, value: str) -> str | None:
    v = value.replace("'", "\\'")
    mapping = {
        "ip": f"[ipv4-addr:value = '{v}']",
        "c2": f"[network-traffic:dst_ref.type = 'domain-name' OR network-traffic:dst_ref.type = 'ipv4-addr']",
        "domain": f"[domain-name:value = '{v}']",
        "url": f"[url:value = '{v}']",
        "email": f"[email-addr:value = '{v}']",
        "md5": f"[file:hashes.'MD5' = '{v}']",
        "sha1": f"[file:hashes.'SHA-1' = '{v}']",
        "sha256": f"[file:hashes.'SHA-256' = '{v}']",
        "filepath": f"[file:name = '{v}']",
        "registry": f"[windows-registry-key:key = '{v}']",
        "mutex": f"[mutex:name = '{v}']",
        "useragent": f"[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = '{v}']",
    }
    if ioc_type == "c2":
        # C2 可能是域名、IP 或 URL，按内容推断
        if value.startswith("http"):
            return f"[url:value = '{v}']"
        try:
            import ipaddress

            ipaddress.ip_address(value)
            return f"[ipv4-addr:value = '{v}']"
        except ValueError:
            return f"[domain-name:value = '{v}']"
    return mapping.get(ioc_type)


def to_openioc(iocs: list) -> str:
    """生成 OpenIOC 1.1 XML。"""
    root = ET.Element("ioc", {
        "id": str(uuid.uuid4()),
        "last-modified": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
        "xmlns": "http://schemas.mandiant.com/2010/ioc",
        "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
    })
    ET.SubElement(root, "short_description").text = "MalScope 导出的威胁指标"
    ET.SubElement(root, "description").text = "由 MalScope 恶意软件样本智能分析平台自动生成"
    definition = ET.SubElement(root, "definition")

    indicator = ET.SubElement(definition, "Indicator", {"operator": "OR", "id": str(uuid.uuid4())})
    for i in iocs:
        ioc_type = _get(i, "ioc_type")
        value = str(_get(i, "value"))
        item_id = _term_id(ioc_type)
        if item_id is None:
            continue
        node = ET.SubElement(indicator, "IndicatorItem", {
            "id": str(uuid.uuid4()),
            "condition": "is",
        })
        ctx = ET.SubElement(node, "Context", {
            "document": "FileItem" if ioc_type in ("md5", "sha1", "sha256", "filepath") else "Network",
            "search": item_id.split(":")[0],
            "type": item_id.split(":")[1],
        })
        ET.SubElement(ctx, "Parameter", {"name": "value"}).text = value
        content = ET.SubElement(node, "Content", {"type": "string"})
        content.text = value

    _indent(root)
    return ET.tostring(root, encoding="unicode", xml_declaration=True)


def _term_id(ioc_type: str) -> str | None:
    return {
        "md5": "FileItem:FileHash",
        "sha1": "FileItem:FileHash",
        "sha256": "FileItem:FileHash",
        "filepath": "FileItem:FullPath",
        "ip": "Network:DestinationIp",
        "c2": "Network:DestinationIp",
        "domain": "Network:DnsQuery",
        "url": "Network:Url",
        "registry": "RegistryItem:KeyPath",
        "mutex": "ProcessItem:MutexName",
        "email": "Email:From",
    }.get(ioc_type)


def _indent(elem, level=0):
    pad = "\n" + "  " * level
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = pad + "  "
        for child in elem:
            _indent(child, level + 1)
        if not child.tail or not child.tail.strip():
            child.tail = pad
    if level and (not elem.tail or not elem.tail.strip()):
        elem.tail = pad


EXPORTERS = {"csv": to_csv, "json": to_json, "stix": to_stix, "openioc": to_openioc}


def export(iocs: list, fmt: str) -> str:
    func = EXPORTERS.get(fmt.lower())
    if not func:
        raise ValueError(f"不支持的导出格式：{fmt}")
    return func(iocs)
