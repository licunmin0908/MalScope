"""端到端冒烟测试：上传 → 静态分析 → 动态沙箱分析 → IOC 提取 → 报告生成。

运行方式（在 backend 目录下）：
    .venv\\Scripts\\python.exe tests\\smoke_pipeline.py [样本路径]

默认使用系统自带 notepad.exe 作为无害样本验证流水线连通性。
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

from app.db import models  # noqa: E402
from app.db.session import SessionLocal, init_db  # noqa: E402
from app.services import analysis_service, report_service, sample_service  # noqa: E402


def main() -> int:
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(r"C:\Windows\System32\notepad.exe")
    if not src.exists():
        print(f"[!] 样本不存在：{src}")
        return 2

    print("=" * 70)
    print("MalScope 端到端流水线冒烟测试")
    print("=" * 70)
    init_db()
    db = SessionLocal()
    tmp = Path(tempfile.mkdtemp(prefix="malscope_smoke_"))
    local = tmp / src.name
    shutil.copy2(src, local)

    try:
        # 1) 入库
        sample, created = sample_service.create_sample(db, local, src.name, upload_ip="127.0.0.1")
        print(f"\n[1] 样本入库：id={sample.id} 新建={created}")
        print(f"    SHA256={sample.sha256}")
        print(f"    MD5={sample.md5}  SSDEEP={sample.ssdeep}")
        print(f"    类型={sample.file_kind} 大小={sample.file_size}")

        # 2) 静态分析
        task = analysis_service.create_task(db, sample.id, "static")
        analysis_service.run_task(db, task.id)
        db.refresh(task)
        print(f"\n[2] 静态分析任务：状态={task.status} 耗时={task.duration_ms}ms")
        if task.error_message:
            print(f"    错误：{task.error_message}")
        static = sample.static_results[-1] if sample.static_results else None
        if static:
            print(f"    风险评分={static.risk_score} 等级={static.risk_level}")
            print(f"    加壳检测={static.packer_detected} ({static.packer_name}) 置信度={static.packer_confidence}")
            print(f"    节区数={len(static.sections)} 导入函数高危={sum(1 for i in static.imports if i.risk_level in ('high','critical'))}")
            print(f"    可疑特征数={len(static.suspicious_features or [])}")
            print(f"    YARA 命中={len(static.yara_matches)}")
            for f in (static.suspicious_features or [])[:6]:
                print(f"      - [{f['severity']}] {f['name']}: {f['description'][:60]}")
            for m in static.yara_matches[:5]:
                print(f"      * YARA: {m.rule_name} ({m.severity})")

        # 3) 动态沙箱分析（mock 驱动）
        task2 = analysis_service.create_task(db, sample.id, "dynamic")
        analysis_service.run_task(db, task2.id)
        db.refresh(task2)
        dyn = sample.dynamic_results[-1] if sample.dynamic_results else None
        print(f"\n[3] 动态沙箱任务：状态={task2.status} 驱动={(dyn.sandbox_driver if dyn else '-')}")
        if dyn:
            print(f"    行为判定={dyn.verdict} 动态风险分={dyn.risk_score}")
            s = dyn.behavior_summary or {}
            print(f"    进程={s.get('process_count')} 文件={s.get('file_event_count')} "
                  f"注册表={s.get('registry_event_count')} 网络={s.get('network_count')} C2={s.get('c2_count')}")
            print(f"    反分析检测={dyn.anti_analysis_detected} 反逃逸事件={len(dyn.evasion_events or [])}")
            print(f"    ATT&CK 技术={len(dyn.attck_techniques or [])}")
            for t in (dyn.attck_techniques or [])[:8]:
                print(f"      - {t['id']} {t['name']}")

        # 4) IOC
        iocs = list(sample.iocs)
        print(f"\n[4] IOC 提取：共 {len(iocs)} 条")
        by_type: dict[str, int] = {}
        for i in iocs:
            by_type[i.ioc_type] = by_type.get(i.ioc_type, 0) + 1
        print(f"    分布：{by_type}")
        for i in sorted(iocs, key=lambda x: x.threat_score, reverse=True)[:8]:
            print(f"      - [{i.ioc_type}] {i.value[:70]} (威胁分 {i.threat_score}, 来源 {i.source})")

        # 5) 报告
        rep_html = report_service.generate_report(db, sample, fmt="html")
        rep_pdf = report_service.generate_report(db, sample, fmt="pdf")
        print(f"\n[5] 报告生成：HTML={rep_html.file_size}B PDF={rep_pdf.file_size}B")
        print(f"    HTML: {rep_html.file_path}")
        print(f"    PDF : {rep_pdf.file_path}")

        print("\n" + "=" * 70)
        print("流水线测试完成 ✅")
        print("=" * 70)
        return 0
    finally:
        db.close()
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
