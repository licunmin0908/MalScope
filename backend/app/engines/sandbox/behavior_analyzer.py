"""动态行为分析与 ATT&CK 映射。

输入：orchestrator 返回的原始沙箱日志。
输出：归一化后的进程树、行为事件、文件/注册表/网络记录、ATT&CK 技术映射、
反逃逸事件、行为摘要与动态风险评分。
"""

from __future__ import annotations

import datetime as dt

from app.core.constants import ATTACK_MAPPING
from app.core.logging import get_logger
from app.engines.sandbox.c2_detect import analyze_flows

logger = get_logger("sandbox.behavior")

# 行为动作 -> ATT&CK（补充 ATTACK_MAPPING 未覆盖的动作）
_ACTION_ATTACK = {
    "process_create": "process_create",
    "process_exit": None,
    "file_create": "file_create",
    "file_drop": "file_drop",
    "file_write": "file_create",
    "file_delete": "file_delete",
    "file_encrypt": "file_encrypt",
    "registry_set": "registry_set",
    "registry_persistence": "registry_persistence",
    "network_connect": "network_connect",
    "network_dns": "dns_query",
    "network_c2": "c2_beacon",
    "check_debugger": "antidebug",
    "check_vm": "antivm",
    "self_delete": "self_delete",
    "terminate_process": "defense_evasion_registry",
    "delete_shadow_copies": "ransomware_note",
    "inject": "process_injection",
    "keylog": "keylogging",
    "screenshot": "screenshot",
    "download": "download_exec",
}

_SEVERITY_WEIGHT = {"critical": 22, "high": 11, "medium": 4, "low": 1, "info": 0}


def _parse_ts(value) -> dt.datetime:
    if isinstance(value, dt.datetime):
        return value
    if isinstance(value, str):
        try:
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return dt.datetime.now(dt.timezone.utc)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed
    return dt.datetime.now(dt.timezone.utc)


def _attach_attack(event: dict) -> None:
    action = event.get("action", "")
    mapping_key = _ACTION_ATTACK.get(action)
    if mapping_key is None:
        # 尝试从 category 兜底
        mapping_key = {
            "network": "network_connect",
            "registry": "registry_set",
            "antidebug": "antidebug",
            "memory": "process_injection",
        }.get(event.get("category", ""))
    if mapping_key and mapping_key in ATTACK_MAPPING:
        info = ATTACK_MAPPING[mapping_key]
        event["attck_technique_id"] = info["id"]
        event["attck_technique"] = f"{info['name']} ({info['tactic']})"


def analyze_behaviors(raw: dict) -> dict:
    """归一化并分析沙箱原始日志。"""
    log = raw.get("log", {}) or {}

    processes = []
    for p in log.get("processes", []):
        processes.append({
            "pid": int(p.get("pid", 0)),
            "ppid": int(p["ppid"]) if p.get("ppid") is not None else None,
            "name": p.get("name") or "unknown",
            "path": p.get("path"),
            "cmdline": p.get("cmdline"),
            "user": p.get("user"),
            "integrity_level": p.get("integrity_level"),
            "is_injected": bool(p.get("is_injected")),
            "is_elevated": bool(p.get("is_elevated")),
            "modules": p.get("modules"),
            "child_count": int(p.get("child_count", 0)),
        })

    events = []
    severity_counter = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    attck_seen: dict[str, dict] = {}
    for e in log.get("events", []):
        event = {
            "timestamp": _parse_ts(e.get("timestamp")),
            "category": e.get("category", "system"),
            "action": e.get("action", "unknown"),
            "object": _truncate(e.get("object")),
            "result": e.get("result"),
            "pid": e.get("pid"),
            "process_name": e.get("process_name"),
            "severity": e.get("severity", "info"),
            "detail": e.get("detail"),
        }
        _attach_attack(event)
        severity_counter[event["severity"]] = severity_counter.get(event["severity"], 0) + 1
        if event.get("attck_technique_id"):
            attck_seen[event["attck_technique_id"]] = {
                "id": event["attck_technique_id"],
                "name": event["attck_technique"],
            }
        events.append(event)

    file_events = []
    dropped_files = []
    for f in log.get("file_events", []):
        row = {
            "timestamp": _parse_ts(f.get("timestamp")),
            "action": f.get("action", "unknown"),
            "path": _truncate(f.get("path"), 1024),
            "new_path": _truncate(f.get("new_path"), 1024),
            "pid": f.get("pid"),
            "process_name": f.get("process_name"),
            "size": f.get("size"),
            "sha256": f.get("sha256"),
            "is_autorun": bool(f.get("is_autorun")),
            "is_ransomware": bool(f.get("is_ransomware")),
            "is_dropped": bool(f.get("is_dropped")),
        }
        file_events.append(row)
        if row["is_dropped"] and row["action"] in ("create", "write"):
            dropped_files.append({"path": row["path"], "size": row["size"], "sha256": row["sha256"]})

    registry_events = []
    for r in log.get("registry_events", []):
        registry_events.append({
            "timestamp": _parse_ts(r.get("timestamp")),
            "action": r.get("action", "set"),
            "key_path": _truncate(r.get("key_path"), 1024),
            "value_name": r.get("value_name"),
            "value_data": _truncate(r.get("value_data")),
            "pid": r.get("pid"),
            "process_name": r.get("process_name"),
            "is_persistence": bool(r.get("is_persistence")),
            "is_hijack": bool(r.get("is_hijack")),
            "is_defense_evasion": bool(r.get("is_defense_evasion")),
        })

    network_flows = []
    for n in log.get("network_events", []):
        network_flows.append({
            "timestamp": _parse_ts(n.get("timestamp")),
            "protocol": n.get("protocol", "TCP"),
            "src_ip": n.get("src_ip"),
            "src_port": n.get("src_port"),
            "dst_ip": n.get("dst_ip"),
            "dst_port": n.get("dst_port"),
            "domain": n.get("domain"),
            "url": n.get("url"),
            "http_method": n.get("http_method"),
            "user_agent": n.get("user_agent"),
            "tls_sni": n.get("tls_sni"),
            "dns_query": n.get("dns_query"),
            "direction": n.get("direction"),
            "is_c2": bool(n.get("is_c2")),
            "c2_confidence": int(n.get("c2_confidence", 0)),
            "c2_reason": n.get("c2_reason"),
            "raw": n,
        })
    c2_stats = analyze_flows(network_flows)

    evasion_events = list(log.get("evasion_events", []))
    anti_analysis = bool(evasion_events) or any(
        e["action"] in ("check_debugger", "check_vm") for e in events
    )

    # 风险评分
    score = 0
    for sev, count in severity_counter.items():
        score += _SEVERITY_WEIGHT.get(sev, 0) * count
    score += min(c2_stats["c2_count"] * 15, 30)
    if any(f["is_ransomware"] for f in file_events):
        score += 30
    if anti_analysis:
        score += 12
    if any(r["is_persistence"] for r in registry_events):
        score += 10
    score = max(0, min(score, 100))

    if score >= 70:
        verdict = "malicious"
    elif score >= 40:
        verdict = "suspicious"
    elif events or file_events or network_flows:
        verdict = "clean"
    else:
        verdict = "unknown"

    behavior_summary = {
        "process_count": len(processes),
        "event_count": len(events),
        "file_event_count": len(file_events),
        "registry_event_count": len(registry_events),
        "network_count": len(network_flows),
        "c2_count": c2_stats["c2_count"],
        "dga_domains": c2_stats["dga_domains"],
        "dropped_file_count": len(dropped_files),
        "persistence_count": sum(1 for r in registry_events if r["is_persistence"]),
        "ransomware_files": sum(1 for f in file_events if f["is_ransomware"]),
        "severity": severity_counter,
        "categories": _count_by(events, "category"),
        "command_lines": [p["cmdline"] for p in processes if p.get("cmdline")][:20],
    }

    return {
        "sandbox_driver": raw.get("sandbox_driver"),
        "vm_name": raw.get("vm_name"),
        "snapshot": raw.get("snapshot"),
        "guest_os": log.get("guest_os") or raw.get("guest_os"),
        "duration_sec": raw.get("duration_sec", 0),
        "status": raw.get("status", "success"),
        "verdict": verdict,
        "risk_score": score,
        "behavior_summary": behavior_summary,
        "attck_techniques": list(attck_seen.values()),
        "evasion_events": evasion_events,
        "anti_analysis_detected": anti_analysis,
        "dropped_files": dropped_files,
        "processes": processes,
        "events": events,
        "network_flows": network_flows,
        "file_events": file_events,
        "registry_events": registry_events,
        "error": raw.get("error"),
    }


def _truncate(value, limit: int = 2000):
    if value is None:
        return None
    s = str(value)
    return s[:limit]


def _count_by(items: list[dict], key: str) -> dict:
    counts: dict[str, int] = {}
    for item in items:
        k = item.get(key, "unknown")
        counts[k] = counts.get(k, 0) + 1
    return counts
