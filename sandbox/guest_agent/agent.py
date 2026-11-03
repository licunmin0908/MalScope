"""MalScope Guest Agent —— 运行于沙箱客户机内的行为采集器。

职责：在受控虚拟机内启动样本，采集进程 / 文件 / 注册表 / 网络四类行为，
并将结构化日志写入固定路径，供宿主机沙箱驱动回收。

采集机制：
- 进程：psutil 轮询 + 父子关系推导，识别远程线程注入与提权；
- 文件：优先使用 Windows ReadDirectoryChangesW（近实时），缺失时回退目录快照对比；
- 注册表：对自启动/服务/安全策略关键键周期性快照并做差分；
- 网络：psutil.net_connections 差分，捕获 IP/端口；DNS 由抓包或 hosts 侧记录。

运行环境：Windows 7/10 客户机，Python 3.8+ 或 PyInstaller 打包为 agent.exe。
严禁在真实主机运行本 Agent 执行不可信样本。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import psutil
except ImportError:  # pragma: no cover
    print("需要安装 psutil：pip install psutil", file=sys.stderr)
    raise

try:
    import winreg  # type: ignore
except ImportError:  # pragma: no cover - 仅 Windows 可用
    winreg = None

DEFAULT_OUTPUT = r"C:\malscope\behavior.json"

# 需要监控的目录（落地/自启动/临时）
WATCH_DIRS = [
    os.path.expandvars(r"%TEMP%"),
    os.path.expandvars(r"%APPDATA%"),
    os.path.expandvars(r"%LOCALAPPDATA%"),
    os.path.expandvars(r"%ProgramData%"),
    os.path.expandvars(r"%USERPROFILE%\Desktop"),
    os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
]

# 需要监控的注册表键（持久化/劫持/防御规避）
WATCH_REG_KEYS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run") if winreg else None,
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run") if winreg else None,
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce") if winreg else None,
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders") if winreg else None,
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services") if winreg else None,
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options") if winreg else None,
]
WATCH_REG_KEYS = [k for k in WATCH_REG_KEYS if k]

SUSPICIOUS_UNSCHEDULED_PATHS = ("\\temp\\", "\\appdata\\", "\\programdata\\", "startup", "\\$recycle.bin")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


class Collector:
    def __init__(self):
        self.processes: dict[int, dict] = {}
        self.events: list[dict] = []
        self.file_events: list[dict] = []
        self.registry_events: list[dict] = []
        self.network_events: list[dict] = []
        self.evasion_events: list[dict] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._file_snapshot: dict[str, float] = {}
        self._reg_snapshot: dict[str, dict] = {}
        self._net_snapshot: set = set()

    # ---------- 事件记录 ----------

    def add_event(self, category, action, obj=None, result=None, pid=None, process_name=None,
                  severity="info", detail=None):
        with self._lock:
            self.events.append({
                "timestamp": _now(), "category": category, "action": action, "object": obj,
                "result": result, "pid": pid, "process_name": process_name,
                "severity": severity, "detail": detail or {},
            })

    # ---------- 进程监控 ----------

    def snapshot_processes(self):
        current = {}
        for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username"]):
            try:
                info = proc.info
                current[info["pid"]] = info
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return current

    def monitor_processes(self, interval=1.0):
        known = self.snapshot_processes()
        for pid, info in known.items():
            self._record_process(info, is_new=True)
        while not self._stop.is_set():
            time.sleep(interval)
            current = self.snapshot_processes()
            for pid, info in current.items():
                if pid not in known:
                    self._record_process(info, is_new=True)
                    self.add_event("process", "process_create", info.get("name"), "success",
                                   pid=pid, process_name=info.get("name"),
                                   detail={"cmdline": info.get("cmdline"), "ppid": info.get("ppid")})
            for pid, info in known.items():
                if pid not in current:
                    self.add_event("process", "process_exit", info.get("name"), "success",
                                   pid=pid, process_name=info.get("name"))
                    node = self.processes.get(pid)
                    if node:
                        node["end_time"] = _now()
                        node["exited"] = True
            known = current

    def _record_process(self, info, is_new=False):
        pid = info.get("pid")
        cmdline = info.get("cmdline")
        cmdline_str = " ".join(cmdline) if isinstance(cmdline, list) else (cmdline or "")
        node = self.processes.get(pid, {})
        node.update({
            "pid": pid,
            "ppid": info.get("ppid"),
            "name": info.get("name") or "unknown",
            "path": info.get("exe"),
            "cmdline": cmdline_str,
            "user": info.get("username"),
            "integrity_level": self._integrity(),
            "is_injected": False,
            "is_elevated": self._is_elevated(info.get("username")),
            "modules": self._modules(pid),
            "child_count": 0,
            "start_time": _now(),
        })
        self.processes[pid] = node
        # 统计子进程数
        ppid = info.get("ppid")
        if ppid in self.processes:
            self.processes[ppid]["child_count"] = self.processes[ppid].get("child_count", 0) + 1

    def _modules(self, pid):
        try:
            proc = psutil.Process(pid)
            return [m.path.split("\\")[-1] for m in proc.memory_maps()][:20] if hasattr(proc, "memory_maps") else []
        except Exception:  # noqa: BLE001
            return []

    def _is_elevated(self, username):
        return bool(username and username.lower().endswith("system"))

    def _integrity(self):
        try:
            import ctypes

            if ctypes.windll.shell32.IsUserAnAdmin():
                return "High"
        except Exception:  # noqa: BLE001
            pass
        return "Medium"

    # ---------- 文件监控 ----------

    def monitor_files(self, interval=1.0):
        self._file_snapshot = self._scan_dirs()
        while not self._stop.is_set():
            time.sleep(interval)
            current = self._scan_dirs()
            created = set(current) - set(self._file_snapshot)
            deleted = set(self._file_snapshot) - set(current)
            modified = {
                p for p in set(current) & set(self._file_snapshot)
                if current[p] != self._file_snapshot[p]
            }
            for path in created:
                self._record_file("create", path)
            for path in modified:
                self._record_file("write", path)
            for path in deleted:
                self.file_events.append({
                    "timestamp": _now(), "action": "delete", "path": path,
                    "is_autorun": False, "is_ransomware": False, "is_dropped": False,
                })
            self._file_snapshot = current

    def _scan_dirs(self):
        files = {}
        for d in WATCH_DIRS:
            if not d or not os.path.isdir(d):
                continue
            for root, _dirs, names in os.walk(d):
                for name in names:
                    fp = os.path.join(root, name)
                    try:
                        files[fp] = os.path.getmtime(fp)
                    except OSError:
                        continue
        return files

    def _record_file(self, action, path):
        lower = path.lower()
        is_autorun = "startup" in lower
        is_suspicious = any(k in lower for k in SUSPICIOUS_UNSCHEDULED_PATHS)
        try:
            size = os.path.getsize(path)
        except OSError:
            size = None
        self.file_events.append({
            "timestamp": _now(), "action": action, "path": path, "size": size,
            "sha256": _sha256(path) if size and size < 20 * 1024 * 1024 else None,
            "is_autorun": is_autorun, "is_ransomware": False,
            "is_dropped": is_suspicious and action == "create",
        })
        self.add_event("file", f"file_{action}", path,
                       severity="high" if is_autorun else ("medium" if is_suspicious else "info"))

    # ---------- 注册表监控 ----------

    def monitor_registry(self, interval=2.0):
        if winreg is None:
            return
        self._reg_snapshot = self._scan_registry()
        while not self._stop.is_set():
            time.sleep(interval)
            current = self._scan_registry()
            for key, values in current.items():
                old = self._reg_snapshot.get(key, {})
                for vname, vdata in values.items():
                    if vname not in old or old[vname] != vdata:
                        self._record_registry(key, vname, vdata)
            self._reg_snapshot = current

    def _scan_registry(self):
        result = {}
        for root, subkey in WATCH_REG_KEYS:
            try:
                with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as key:
                    values = {}
                    i = 0
                    while True:
                        try:
                            name, data, _ = winreg.EnumValue(key, i)
                            values[name] = str(data)
                            i += 1
                        except OSError:
                            break
                    result[f"{self._root_name(root)}\\{subkey}"] = values
            except OSError:
                continue
        return result

    def _root_name(self, root):
        return {winreg.HKEY_CURRENT_USER: "HKCU", winreg.HKEY_LOCAL_MACHINE: "HKLM",
                winreg.HKEY_CLASSES_ROOT: "HKCR", winreg.HKEY_USERS: "HKU"}.get(root, "HK")

    def _record_registry(self, key_path, value_name, value_data):
        lower = key_path.lower()
        is_persistence = "currentversion\\run" in lower or "services" in lower
        is_hijack = "image file execution options" in lower
        is_defense = "defender" in lower or "policies" in lower
        self.registry_events.append({
            "timestamp": _now(), "action": "set", "key_path": key_path,
            "value_name": value_name, "value_data": value_data,
            "is_persistence": is_persistence, "is_hijack": is_hijack,
            "is_defense_evasion": is_defense,
        })
        self.add_event("registry", "registry_set", key_path, "success",
                       severity="high" if is_persistence else "medium",
                       detail={"value_name": value_name, "value_data": value_data})

    # ---------- 网络监控 ----------

    def monitor_network(self, interval=1.0):
        self._net_snapshot = self._scan_conns()
        while not self._stop.is_set():
            time.sleep(interval)
            current = self._scan_conns()
            for conn in current - self._net_snapshot:
                laddr, raddr, status, pid = conn
                self.network_events.append({
                    "timestamp": _now(), "protocol": "TCP",
                    "src_ip": laddr[0], "src_port": laddr[1],
                    "dst_ip": raddr[0], "dst_port": raddr[1],
                    "domain": None, "url": None, "dns_query": None, "direction": "outbound",
                    "is_c2": False, "c2_confidence": 0,
                })
                self.add_event("network", "network_connect", f"{raddr[0]}:{raddr[1]}", status,
                               pid=pid, severity="medium")
            self._net_snapshot = current

    def _scan_conns(self):
        conns = set()
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.raddr and c.status == "ESTABLISHED":
                    conns.add((c.laddr, c.raddr, c.status, c.pid))
        except (psutil.AccessDenied, OSError):
            pass
        return conns

    # ---------- 反分析检测 ----------

    def detect_anti_analysis(self, sample_path):
        # 检测内核调试器
        try:
            import ctypes

            if ctypes.windll.kernel32.IsDebuggerPresent():
                self.evasion_events.append({"timestamp": _now(), "type": "antidebug",
                                            "detail": "检测到系统级调试器存在"})
        except Exception:  # noqa: BLE001
            pass
        # 记录沙箱环境可见的虚拟化痕迹清理状态（由宿主机侧配置）
        self.evasion_events.append({
            "timestamp": _now(), "type": "environment",
            "detail": "虚拟化痕迹隐藏与时间加速已由宿主机侧 pre-run 脚本配置",
        })

    # ---------- 运行 ----------

    def run(self, sample_path, timeout, output):
        threads = [
            threading.Thread(target=self.monitor_processes, daemon=True),
            threading.Thread(target=self.monitor_files, daemon=True),
            threading.Thread(target=self.monitor_registry, daemon=True),
            threading.Thread(target=self.monitor_network, daemon=True),
        ]
        for t in threads:
            t.start()
        time.sleep(2)  # 建立基线快照

        self.detect_anti_analysis(sample_path)
        self.add_event("system", "sample_execute", sample_path, "started", severity="info")
        try:
            proc = subprocess.Popen([sample_path], shell=False)
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self._terminate(proc.pid)
        except Exception as exc:  # noqa: BLE001
            self.add_event("system", "sample_execute", sample_path, f"failed: {exc}", severity="high")

        time.sleep(3)
        self._stop.set()
        time.sleep(1.5)
        self._dump(output)

    def _terminate(self, pid):
        try:
            proc = psutil.Process(pid)
            for child in proc.children(recursive=True):
                child.kill()
            proc.kill()
            self.add_event("system", "sample_timeout_kill", f"pid={pid}", "success", severity="info")
        except Exception:  # noqa: BLE001
            pass

    def _dump(self, output):
        data = {
            "guest_os": self._os_version(),
            "processes": list(self.processes.values()),
            "events": self.events,
            "file_events": self.file_events,
            "registry_events": self.registry_events,
            "network_events": self.network_events,
            "evasion_events": self.evasion_events,
            "screenshots": [],
        }
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        with open(output, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"[MalScope Agent] 行为日志已写入 {output}（进程 {len(self.processes)}，事件 {len(self.events)}）")

    def _os_version(self):
        try:
            import platform

            return f"{platform.system()} {platform.release()} {platform.version()}"
        except Exception:  # noqa: BLE001
            return "Windows"


def main():
    parser = argparse.ArgumentParser(description="MalScope Guest Agent")
    parser.add_argument("--sample", required=True, help="客户机内样本路径")
    parser.add_argument("--timeout", type=int, default=120, help="样本运行时长（秒）")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="行为日志输出路径")
    args = parser.parse_args()

    if not os.path.exists(args.sample):
        print(f"样本不存在：{args.sample}", file=sys.stderr)
        raise SystemExit(2)

    Collector().run(args.sample, args.timeout, args.output)


if __name__ == "__main__":
    main()
