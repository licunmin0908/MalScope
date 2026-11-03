"""分析任务服务：静态/动态分析调度与结果持久化。"""

from __future__ import annotations

import datetime as dt
import json
import uuid
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.db import models
from app.engines.static_analysis import engine as static_engine
from app.services import storage
from app.services.ioc_service import save_iocs

logger = get_logger("service.analysis")


def create_task(db: Session, sample_id: str, task_type: str, *, user=None) -> models.AnalysisTask:
    task = models.AnalysisTask(
        id=str(uuid.uuid4()),
        sample_id=sample_id,
        task_type=task_type,
        status="pending",
        progress=0,
        stage="已入队",
        created_by=getattr(user, "id", None),
    )
    db.add(task)
    db.commit()
    db.refresh(task)
    return task


def _utcnow() -> dt.datetime:
    """返回带 UTC 时区的当前时间。"""
    return dt.datetime.now(dt.timezone.utc)


def _as_aware(value: dt.datetime) -> dt.datetime:
    """将可能为 naive 的数据库时间统一视为 UTC。"""
    return value if value.tzinfo is not None else value.replace(tzinfo=dt.timezone.utc)


def _set_status(db: Session, task: models.AnalysisTask, status: str, *, progress: int | None = None,
                stage: str | None = None, error: str | None = None) -> None:
    task.status = status
    if progress is not None:
        task.progress = progress
    if stage is not None:
        task.stage = stage
    if error is not None:
        task.error_message = error
    if status in ("success", "failed", "timeout", "cancelled") and task.finished_at is None:
        task.finished_at = _utcnow()
        if task.started_at:
            task.duration_ms = int(
                (_as_aware(task.finished_at) - _as_aware(task.started_at)).total_seconds() * 1000
            )
    db.commit()


def run_task(db: Session, task_id: str) -> models.AnalysisTask:
    """执行分析任务（同步入口，供后台线程/Celery 调用）。"""
    task = db.get(models.AnalysisTask, task_id)
    if not task:
        raise ValueError(f"任务不存在：{task_id}")
    sample = db.get(models.Sample, task.sample_id)
    if not sample:
        _set_status(db, task, "failed", error="样本不存在")
        return task

    task.started_at = dt.datetime.now(dt.timezone.utc)
    _set_status(db, task, "running", progress=5, stage="开始分析")

    try:
        if task.task_type in ("static", "full"):
            _run_static(db, task, sample)
        if task.task_type in ("dynamic", "full"):
            _run_dynamic(db, task, sample)
        _set_status(db, task, "success", progress=100, stage="完成")
    except Exception as exc:  # noqa: BLE001
        logger.exception("分析任务失败：%s", exc)
        _set_status(db, task, "failed", error=str(exc), stage="失败")
    return task


def _run_static(db: Session, task: models.AnalysisTask, sample: models.Sample) -> None:
    _set_status(db, task, "running", progress=15, stage="静态分析中")
    with storage.materialize(sample) as path:
        result = static_engine.analyze_file(path)
        _persist_static(db, task, sample, result)
        # 从静态结果提取 IOC
        from app.engines.threat_intel.ioc_extractor import extract_from_static

        iocs = extract_from_static(result)
        save_iocs(db, sample.id, iocs, source="static")
    _set_status(db, task, "running", progress=60, stage="静态分析完成")


def _persist_static(db: Session, task, sample: models.Sample, result: dict) -> models.StaticAnalysis:
    headers = result.get("headers", {})
    nt = headers.get("nt_headers", {})
    opt = headers.get("optional_header", {})
    hashes = result.get("hashes", {})
    risk = result.get("risk", {})
    packer = result.get("packer", {})
    signature = result.get("signature", {})
    imports = result.get("imports", {})
    strings = result.get("strings", {})

    compile_dt = None
    if headers.get("compile_time_iso"):
        try:
            compile_dt = dt.datetime.fromisoformat(headers["compile_time_iso"])
        except ValueError:
            compile_dt = None

    sa = models.StaticAnalysis(
        sample_id=sample.id,
        task_id=task.id,
        file_kind=result.get("file_type", {}).get("kind", "unknown"),
        file_type_desc=result.get("file_type", {}).get("description"),
        dos_header=headers.get("dos_header"),
        nt_headers=nt,
        optional_header=opt,
        data_directories=headers.get("data_directories"),
        entry_point=headers.get("entry_point"),
        image_base=headers.get("image_base"),
        compile_timestamp=compile_dt,
        compile_timestamp_raw=headers.get("compile_timestamp_raw"),
        pdb_path=(result.get("pe", {}).get("debug") or {}).get("pdb_path"),
        rich_header=result.get("pe", {}).get("rich_header"),
        packer_detected=bool(packer.get("detected")),
        packer_name=packer.get("name"),
        packer_confidence=int(packer.get("confidence", 0)),
        resources=result.get("resources"),
        version_info=result.get("version_info"),
        signature=signature,
        suspicious_features=result.get("features"),
        api_risk_summary=imports.get("summary"),
        behavior_hints=imports.get("behavior_hints"),
        risk_score=int(risk.get("score", 0)),
        risk_level=risk.get("level", "unknown"),
        raw_result=_strip_raw(result),
    )
    db.add(sa)
    db.flush()

    # 节区
    for sec in result.get("sections", []):
        db.add(models.Section(
            analysis_id=sa.id, name=sec["name"], virtual_address=sec["virtual_address"],
            virtual_size=sec["virtual_size"], raw_offset=sec["raw_offset"], raw_size=sec["raw_size"],
            entropy=sec["entropy"], md5=sec.get("md5"), sha256=sec.get("sha256"),
            characteristics=sec["characteristics"], flags=sec["flags"],
            is_executable=sec["is_executable"], is_writable=sec["is_writable"],
            is_readable=sec["is_readable"], is_rwx=sec["is_rwx"],
            is_suspicious=sec["is_suspicious"], suspicion_reason=sec.get("suspicion_reason"),
        ))
    # 导入 / 导出
    for imp in imports.get("imports", []):
        db.add(models.ImportEntry(
            analysis_id=sa.id, dll=imp["dll"], function=imp["function"], ordinal=imp.get("ordinal"),
            risk_category=imp.get("risk_category"), risk_level=imp.get("risk_level"),
            description=imp.get("description"),
        ))
    for exp in result.get("exports", []):
        db.add(models.ExportEntry(
            analysis_id=sa.id, name=exp["name"], ordinal=exp.get("ordinal"),
            address=exp.get("address"), forwarder=exp.get("forwarder"),
        ))
    # 字符串
    for s in strings.get("strings", []):
        db.add(models.ExtractedString(
            analysis_id=sa.id, value=s["value"], encoding=s["encoding"], offset=s["offset"],
            category=s["category"], risk_level=s["risk_level"], is_whitelisted=s["is_whitelisted"],
        ))
    # YARA
    for m in result.get("yara_matches", []):
        db.add(models.YaraMatch(
            analysis_id=sa.id, rule_name=m["rule_name"], namespace=m.get("namespace"),
            description=m.get("description"), severity=m.get("severity"),
            tags=m.get("tags"), matched_strings=m.get("matched_strings"),
        ))

    # 回写样本摘要
    sample.is_pe = bool(result.get("pe", {}).get("is_valid_pe"))
    sample.entropy = float(result.get("overall_entropy", 0.0))
    sample.imphash = headers.get("imphash")
    sample.ssdeep = hashes.get("ssdeep") or sample.ssdeep
    sample.packer = packer.get("name") if packer.get("detected") else None
    sample.is_signed = bool(signature.get("is_signed"))
    sample.signature_subject = signature.get("signer")
    sample.risk_score = int(risk.get("score", 0))
    sample.threat_level = risk.get("level", "unknown")
    db.commit()
    db.refresh(sa)
    return sa


def _strip_raw(result: dict) -> dict:
    """保留精简版原始结果（去掉大字段，避免 JSON 列过大）。"""
    return {
        "summary": result.get("summary"),
        "risk": result.get("risk"),
        "packer": result.get("packer"),
        "string_counts": result.get("strings", {}).get("counts"),
        "highlights": result.get("strings", {}).get("highlights"),
        "tls": result.get("pe", {}).get("tls"),
        "section_overlaps": result.get("pe", {}).get("section_overlaps"),
        "duration_ms": result.get("duration_ms"),
    }


def _run_dynamic(db: Session, task: models.AnalysisTask, sample: models.Sample) -> None:
    from app.engines.sandbox.orchestrator import SandboxOrchestrator
    from app.engines.sandbox.behavior_analyzer import analyze_behaviors

    _set_status(db, task, "running", progress=65, stage="沙箱执行中")
    orchestrator = SandboxOrchestrator()
    with storage.materialize(sample) as path:
        raw = orchestrator.run(sample, path)
    _set_status(db, task, "running", progress=88, stage="行为分析中")
    analyzed = analyze_behaviors(raw)
    _persist_dynamic(db, task, sample, analyzed)

    from app.engines.threat_intel.ioc_extractor import extract_from_dynamic

    iocs = extract_from_dynamic(analyzed)
    save_iocs(db, sample.id, iocs, source="dynamic", dynamic_id=_last_dynamic_id(db, sample.id))


def _last_dynamic_id(db: Session, sample_id: str) -> int | None:
    row = db.scalar(
        select(models.DynamicAnalysis)
        .where(models.DynamicAnalysis.sample_id == sample_id)
        .order_by(models.DynamicAnalysis.id.desc())
    )
    return row.id if row else None


def _persist_dynamic(db: Session, task, sample: models.Sample, data: dict) -> models.DynamicAnalysis:
    da = models.DynamicAnalysis(
        sample_id=sample.id,
        task_id=task.id,
        sandbox_driver=data.get("sandbox_driver", settings.SANDBOX_DRIVER),
        vm_name=data.get("vm_name"),
        snapshot=data.get("snapshot"),
        guest_os=data.get("guest_os"),
        executed_at=dt.datetime.now(dt.timezone.utc),
        duration_sec=int(data.get("duration_sec", 0)),
        status=data.get("status", "success"),
        verdict=data.get("verdict", "unknown"),
        risk_score=int(data.get("risk_score", 0)),
        behavior_summary=data.get("behavior_summary"),
        attck_techniques=data.get("attck_techniques"),
        evasion_events=data.get("evasion_events"),
        anti_analysis_detected=bool(data.get("anti_analysis_detected")),
        dropped_files=data.get("dropped_files"),
    )
    db.add(da)
    db.flush()

    for p in data.get("processes", []):
        db.add(models.ProcessNode(
            dynamic_id=da.id, pid=p["pid"], ppid=p.get("ppid"), name=p["name"], path=p.get("path"),
            cmdline=p.get("cmdline"), user=p.get("user"), integrity_level=p.get("integrity_level"),
            is_injected=p.get("is_injected", False), is_elevated=p.get("is_elevated", False),
            modules=p.get("modules"), child_count=p.get("child_count", 0),
        ))
    for e in data.get("events", []):
        db.add(models.BehaviorEvent(
            dynamic_id=da.id, timestamp=e["timestamp"], category=e["category"], action=e["action"],
            object=e.get("object"), result=e.get("result"), pid=e.get("pid"),
            process_name=e.get("process_name"), severity=e.get("severity", "info"),
            attck_technique_id=e.get("attck_technique_id"), attck_technique=e.get("attck_technique"),
            detail=e.get("detail"),
        ))
    for f in data.get("network_flows", []):
        db.add(models.NetworkFlow(
            dynamic_id=da.id, timestamp=f["timestamp"], protocol=f["protocol"],
            src_ip=f.get("src_ip"), src_port=f.get("src_port"), dst_ip=f.get("dst_ip"),
            dst_port=f.get("dst_port"), domain=f.get("domain"), url=f.get("url"),
            http_method=f.get("http_method"), user_agent=f.get("user_agent"),
            tls_sni=f.get("tls_sni"), dns_query=f.get("dns_query"), direction=f.get("direction"),
            is_c2=f.get("is_c2", False), c2_confidence=f.get("c2_confidence", 0),
            c2_reason=f.get("c2_reason"), raw=f.get("raw"),
        ))
    for fe in data.get("file_events", []):
        db.add(models.FileEvent(
            dynamic_id=da.id, timestamp=fe["timestamp"], action=fe["action"], path=fe["path"],
            new_path=fe.get("new_path"), pid=fe.get("pid"), process_name=fe.get("process_name"),
            size=fe.get("size"), sha256=fe.get("sha256"), is_autorun=fe.get("is_autorun", False),
            is_ransomware=fe.get("is_ransomware", False), is_dropped=fe.get("is_dropped", False),
        ))
    for re_ in data.get("registry_events", []):
        db.add(models.RegistryEvent(
            dynamic_id=da.id, timestamp=re_["timestamp"], action=re_["action"],
            key_path=re_["key_path"], value_name=re_.get("value_name"), value_data=re_.get("value_data"),
            pid=re_.get("pid"), process_name=re_.get("process_name"),
            is_persistence=re_.get("is_persistence", False), is_hijack=re_.get("is_hijack", False),
            is_defense_evasion=re_.get("is_defense_evasion", False),
        ))

    # 融合样本等级
    if data.get("risk_score", 0) >= 70:
        sample.threat_level = "malicious"
    elif data.get("risk_score", 0) >= 40 and sample.threat_level in ("unknown", "clean"):
        sample.threat_level = "suspicious"
    db.commit()
    db.refresh(da)
    return da
