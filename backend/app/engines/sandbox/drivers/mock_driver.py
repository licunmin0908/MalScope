"""Mock 沙箱驱动（用于无虚拟化环境下的功能演示与联调）。

不启动真实虚拟机，而是依据样本自身特征（提取到的域名/IP/URL 字符串、
导入表能力、静态风险）确定性地合成一份结构完整的“客户机行为日志”。

设计要点：
- 以样本 SHA256 作为随机种子，保证同一样本每次运行结果一致（可复现）；
- 生成的日志结构与真实 guest agent 完全一致，便于上层分析逻辑无差别复用；
- 明确标注 driver=mock，避免与真实沙箱结果混淆。
"""

from __future__ import annotations

import datetime as dt
import hashlib
import random
from pathlib import Path

from app.core.logging import get_logger
from app.engines.sandbox.base import SandboxDriver, SandboxRun

logger = get_logger("sandbox.mock")

_WRITABLE_DIRS = [
    r"C:\Users\analyst\AppData\Local\Temp",
    r"C:\Users\analyst\AppData\Roaming",
    r"C:\ProgramData",
    r"C:\Users\analyst\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
]

_RUN_KEYS = [
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SYSTEM\CurrentControlSet\Services\WinDefendSvc",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
]

_CAPABILITY_KEYWORDS = {
    "process_injection": ["createremotethread", "writeprocessmemory", "virtualallocex", "ntcreatethreadex", "setthreadcontext"],
    "ransomware": ["cryptencrypt", "cryptgenkey", "bcryptencrypt", "encryptfile", "vssadmin"],
    "keylogger": ["getasynckeystate", "setwindowshookex", "getkeyboardstate"],
    "antidebug": ["isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess"],
    "antivm": ["vmware", "virtualbox", "vboxservice", "sbiedll"],
    "persistence": ["regsetvalue", "createservice", "schtasks", "currentversion\\run"],
    "download": ["urldownloadtofile", "winhttpopen", "internetopenurl", "downloadfile"],
    "discovery": ["getcomputername", "getusername", "netuserenum", "systeminfo"],
}


class MockDriver(SandboxDriver):
    name = "mock"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._guest_path = ""
        self._log: dict = {}

    @classmethod
    def available(cls) -> bool:
        return True

    def prepare(self) -> None:
        logger.info("[mock] 回滚快照 %s（模拟）", self.snapshot)
        self._log = {}

    def transfer_sample(self, local_path: Path, guest_path: str) -> None:
        self._guest_path = guest_path
        logger.info("[mock] 投递样本到客户机 %s（模拟）", guest_path)

    def execute(self, guest_path: str) -> None:
        """合成客户机行为日志。"""
        self._log = self._synthesize()

    def collect_log(self) -> dict:
        return self._log

    def revert(self) -> None:
        logger.info("[mock] 已还原快照，清除环境残留（模拟）")

    # ---------------- 行为合成 ----------------

    def _synthesize(self) -> dict:
        hints = self.options.get("hints", {})
        seed_src = hints.get("sha256") or self._guest_path
        rng = random.Random(int(hashlib.sha256(seed_src.encode()).hexdigest()[:12], 16))

        base = dt.datetime.now(dt.timezone.utc)
        t = [0.0]

        def ts() -> str:
            t[0] += rng.uniform(0.05, 1.6)
            return (base + dt.timedelta(seconds=t[0])).isoformat()

        domains = hints.get("domains", []) or []
        ips = hints.get("ips", []) or []
        urls = hints.get("urls", []) or []
        caps = self._capabilities(hints)

        # 行为强度与静态研判等级一致：无害样本不应合成出满级恶意行为。
        level = hints.get("risk_level") or "unknown"
        intensity = {"malicious": 1.0, "suspicious": 0.6, "clean": 0.0, "unknown": 0.3}.get(level, 0.3)

        sample_name = hints.get("sample_name") or "sample.exe"
        parent_pid = 2144

        processes = [{
            "pid": parent_pid, "ppid": 1024, "name": sample_name,
            "path": self._guest_path, "cmdline": self._guest_path,
            "user": "analyst", "integrity_level": "Medium",
            "is_injected": False, "is_elevated": False, "modules": ["kernel32.dll", "user32.dll", "ntdll.dll"],
            "child_count": 0,
        }]
        events: list[dict] = []
        file_events: list[dict] = []
        registry_events: list[dict] = []
        network_events: list[dict] = []
        evasion_events: list[dict] = []

        events.append({
            "timestamp": ts(), "category": "process", "action": "process_create",
            "object": sample_name, "result": "success", "pid": parent_pid,
            "process_name": sample_name, "severity": "info",
            "detail": {"image": self._guest_path},
        })

        # 反调试/反虚拟机探测
        if intensity >= 0.4 and "antidebug" in caps:
            evasion_events.append({"timestamp": ts(), "type": "antidebug", "detail": "调用 IsDebuggerPresent 检测调试器"})
            events.append({
                "timestamp": ts(), "category": "antidebug", "action": "check_debugger",
                "object": "IsDebuggerPresent", "result": "not_found", "pid": parent_pid,
                "process_name": sample_name, "severity": "medium",
            })
        if intensity >= 0.4 and "antivm" in caps:
            evasion_events.append({"timestamp": ts(), "type": "antivm", "detail": "读取注册表探测 VirtualBox/VMware 痕迹"})
            events.append({
                "timestamp": ts(), "category": "antidebug", "action": "check_vm",
                "object": "HKLM\\HARDWARE\\Description\\System", "result": "detected",
                "pid": parent_pid, "process_name": sample_name, "severity": "medium",
            })

        # 释放落地文件
        if intensity >= 0.6:
            drop_count = rng.randint(1, 4)
        elif intensity > 0:
            drop_count = 1
        else:
            drop_count = 0
        for i in range(drop_count):
            d = rng.choice(_WRITABLE_DIRS)
            fname = rng.choice(["svc.exe", "upd.dat", "payload.bin", "config.json", "temp.tmp", "note.txt"])
            path = f"{d}\\{fname}"
            is_startup = "Startup" in d
            file_events.append({
                "timestamp": ts(), "action": "create", "path": path, "pid": parent_pid,
                "process_name": sample_name, "size": rng.randint(512, 200000),
                "is_autorun": is_startup, "is_dropped": True, "is_ransomware": False,
            })
            events.append({
                "timestamp": ts(), "category": "file", "action": "file_create",
                "object": path, "result": "success", "pid": parent_pid,
                "process_name": sample_name, "severity": "high" if is_startup else "medium",
            })

        # 勒索加密行为（仅在蛛丝马迹充分且静态研判为恶意时合成）
        if intensity >= 0.85 and "ransomware" in caps:
            for i in range(rng.randint(5, 12)):
                path = rf"C:\Users\analyst\Documents\document_{i}.{rng.choice(['pdf','docx','jpg','xlsx'])}"
                file_events.append({
                    "timestamp": ts(), "action": "write", "path": path, "new_path": path + ".locked",
                    "pid": parent_pid, "process_name": sample_name,
                    "is_ransomware": True,
                })
            note = r"C:\Users\analyst\Desktop\README_DECRYPT.txt"
            file_events.append({
                "timestamp": ts(), "action": "create", "path": note, "pid": parent_pid,
                "process_name": sample_name, "size": 1024, "is_ransomware": True, "is_dropped": True,
            })
            events.append({
                "timestamp": ts(), "category": "file", "action": "file_encrypt",
                "object": "批量文件加密", "result": "success", "pid": parent_pid,
                "process_name": sample_name, "severity": "critical",
                "detail": {"algorithm": rng.choice(["AES-256-CBC", "ChaCha20", "RSA-2048+AES"])},
            })
            events.append({
                "timestamp": ts(), "category": "system", "action": "delete_shadow_copies",
                "object": "vssadmin delete shadows /all /quiet", "result": "success",
                "pid": parent_pid, "process_name": sample_name, "severity": "critical",
            })

        # 注册表持久化
        if intensity >= 0.5 and ("persistence" in caps or rng.random() < 0.7):
            key = rng.choice(_RUN_KEYS)
            registry_events.append({
                "timestamp": ts(), "action": "set", "key_path": key,
                "value_name": rng.choice(["Updater", "WindowsUpdate", "SystemCheck", "svc"]),
                "value_data": rf"C:\Users\analyst\AppData\Roaming\svc.exe",
                "pid": parent_pid, "process_name": sample_name,
                "is_persistence": "Run" in key, "is_hijack": False, "is_defense_evasion": False,
            })
            events.append({
                "timestamp": ts(), "category": "registry", "action": "registry_set",
                "object": key, "result": "success", "pid": parent_pid,
                "process_name": sample_name, "severity": "high",
            })

        # 防御规避：终止安全进程
        if intensity >= 0.7 and "antidebug" in caps and rng.random() < 0.6:
            events.append({
                "timestamp": ts(), "category": "system", "action": "terminate_process",
                "object": "MsMpEng.exe", "result": "failed", "pid": parent_pid,
                "process_name": sample_name, "severity": "high",
            })

        # 子进程
        if intensity >= 0.6 and caps.get("spawn_cmd"):
            child_pid = parent_pid + 100
            processes.append({
                "pid": child_pid, "ppid": parent_pid, "name": "cmd.exe",
                "path": r"C:\Windows\System32\cmd.exe",
                "cmdline": r'cmd.exe /c schtasks /create /tn Update /tr "svc.exe" /sc onlogon',
                "user": "analyst", "integrity_level": "Medium", "is_injected": False,
                "is_elevated": False, "modules": ["kernel32.dll"], "child_count": 0,
            })
            events.append({
                "timestamp": ts(), "category": "process", "action": "process_create",
                "object": "cmd.exe", "result": "success", "pid": child_pid,
                "process_name": "cmd.exe", "severity": "medium",
                "detail": {"cmdline": r'cmd /c schtasks /create /tn Update'},
            })
            processes[0]["child_count"] += 1

        # 网络外联 / C2
        targets = []
        for d in domains[:3]:
            targets.append({"kind": "domain", "value": d})
        for ip in ips[:3]:
            targets.append({"kind": "ip", "value": ip})
        if intensity < 0.5:
            targets = []
        if not targets and intensity >= 0.5 and ("download" in caps or rng.random() < 0.5):
            targets.append({"kind": "domain", "value": f"{rng.choice(['cdn','api','update','sync'])}.{rng.choice(['dyncdn','ru-zone','top-domain','xyz-host'])}.{rng.choice(['com','net','ru','xyz'])}"})

        for idx, tgt in enumerate(targets):
            is_c2 = idx == 0 or rng.random() < 0.6
            port = rng.choice([80, 443, 8080, 8443])
            domain = tgt["value"] if tgt["kind"] == "domain" else None
            ip = tgt["value"] if tgt["kind"] == "ip" else f"203.0.113.{rng.randint(2,250)}"
            network_events.append({
                "timestamp": ts(), "protocol": "TCP", "src_ip": "10.0.2.15",
                "src_port": rng.randint(49152, 65535), "dst_ip": ip, "dst_port": port,
                "domain": domain, "url": f"http://{domain or ip}/gate.php?cmd=ping" if is_c2 else None,
                "http_method": "POST" if is_c2 else "GET",
                "user_agent": rng.choice(["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Mozilla/4.0 (compatible; MSIE 7.0)"]),
                "tls_sni": domain if port == 443 else None,
                "dns_query": domain, "direction": "outbound",
                "is_c2": is_c2, "c2_confidence": 85 if is_c2 else 30,
                "c2_reason": "心跳式 POST 报文 + 可疑域名" if is_c2 else None,
            })
            events.append({
                "timestamp": ts(), "category": "network", "action": "network_connect",
                "object": f"{domain or ip}:{port}", "result": "success", "pid": parent_pid,
                "process_name": sample_name, "severity": "high" if is_c2 else "medium",
            })

        # DNS 查询
        for d in (domains[:5] if intensity >= 0.5 else []):
            network_events.append({
                "timestamp": ts(), "protocol": "DNS", "src_ip": "10.0.2.15", "dst_ip": "10.0.2.3",
                "domain": d, "dns_query": d, "direction": "outbound", "is_c2": False,
            })

        # 清理痕迹
        if intensity >= 0.7 and ("antidebug" in caps or caps.get("self_delete")):
            events.append({
                "timestamp": ts(), "category": "system", "action": "self_delete",
                "object": self._guest_path, "result": "pending", "pid": parent_pid,
                "process_name": sample_name, "severity": "medium",
            })
            evasion_events.append({"timestamp": ts(), "type": "self_delete", "detail": "样本尝试删除自身以清除痕迹"})

        events.append({
            "timestamp": ts(), "category": "process", "action": "process_exit",
            "object": sample_name, "result": "success", "pid": parent_pid,
            "process_name": sample_name, "severity": "info",
        })

        return {
            "processes": processes,
            "events": events,
            "file_events": file_events,
            "registry_events": registry_events,
            "network_events": network_events,
            "evasion_events": evasion_events,
            "screenshots": [],
            "guest_os": "Windows 10 x64 (Mock)",
        }

    def _capabilities(self, hints: dict) -> dict:
        blob = " ".join([
            " ".join(hints.get("apis", [])),
            " ".join(hints.get("strings_sample", [])),
        ]).lower()
        caps: dict = {}
        for cap, keywords in _CAPABILITY_KEYWORDS.items():
            caps[cap] = any(kw in blob for kw in keywords)
        caps["spawn_cmd"] = any(kw in blob for kw in ("createprocess", "winexec", "shellexecute", "cmd.exe", "schtasks"))
        caps["self_delete"] = any(kw in blob for kw in ("deletefile", "movefileex"))
        return caps
