"""安全分析报告生成服务：HTML 模板渲染 + PDF 导出。

报告涵盖：样本信息、多算法哈希、静态分析（区段/导入表/字符串/YARA/加壳）、
动态行为（进程树/文件/注册表/网络/C2）、IOC 清单、ATT&CK 矩阵与处置建议。
"""

from __future__ import annotations

import datetime as dt
import io
import uuid
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.db import models

logger = get_logger("service.report")

TEMPLATE_DIR = Path(__file__).resolve().parents[1] / "templates"

_env = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=select_autoescape(["html", "xml"]),
    trim_blocks=True,
    lstrip_blocks=True,
)

LEVEL_CN = {"malicious": "恶意", "suspicious": "可疑", "clean": "无害", "unknown": "未知"}
SEVERITY_CN = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}


def build_context(db: Session, sample: models.Sample, task_id: str | None = None) -> dict:
    static = None
    dynamic = None
    if sample.static_results:
        static = sample.static_results[-1]
    if sample.dynamic_results:
        dynamic = sample.dynamic_results[-1]
    iocs = list(sample.iocs)
    iocs.sort(key=lambda x: x.threat_score, reverse=True)

    return {
        "generated_at": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "platform": settings.APP_NAME,
        "sample": sample,
        "static": static,
        "dynamic": dynamic,
        "iocs": iocs,
        "sections": sorted(static.sections, key=lambda s: s.raw_offset) if static else [],
        "imports": _risky_imports(static) if static else [],
        "yara_matches": static.yara_matches if static else [],
        "features": (static.suspicious_features or []) if static else [],
        "processes": dynamic.processes if dynamic else [],
        "events": sorted(dynamic.events, key=lambda e: e.timestamp)[:300] if dynamic else [],
        "network_flows": dynamic.network_flows if dynamic else [],
        "file_events": dynamic.file_events if dynamic else [],
        "registry_events": dynamic.registry_events if dynamic else [],
        "attck": (dynamic.attck_techniques or []) if dynamic else [],
        "level_cn": LEVEL_CN,
        "severity_cn": SEVERITY_CN,
        "top_level": LEVEL_CN.get(sample.threat_level, "未知"),
        "conclusion": _conclusion(sample, static, dynamic),
        "suggestions": _suggestions(sample, static, dynamic),
    }


def _risky_imports(static: models.StaticAnalysis) -> list[models.ImportEntry]:
    return [
        imp for imp in static.imports if imp.risk_level in ("high", "critical")
    ][:100]


def _conclusion(sample, static, dynamic) -> str:
    parts = []
    parts.append(f"样本「{sample.original_filename}」危害等级判定为【{LEVEL_CN.get(sample.threat_level, '未知')}】，综合风险评分 {sample.risk_score}/100。")
    if static and static.packer_detected:
        parts.append(f"样本疑似使用 {static.packer_name} 加壳，建议先脱壳后再深入分析。")
    if static and static.risk_level == "malicious":
        parts.append("静态特征显示样本具备明确恶意能力。")
    if dynamic:
        if dynamic.anti_analysis_detected:
            parts.append("动态运行中检测到反分析行为，说明样本具备对抗沙箱的意图。")
        c2_count = sum(1 for f in dynamic.network_flows if f.is_c2)
        if c2_count:
            parts.append(f"捕获到 {c2_count} 条疑似 C2 外联流量。")
    return " ".join(parts)


def _suggestions(sample, static, dynamic) -> list[str]:
    tips = []
    if sample.threat_level == "malicious":
        tips.append("立即隔离该样本，禁止在生产主机上执行。")
        tips.append("将样本哈希与 IOC 同步至终端防护与威胁情报平台进行全网排查。")
    if static and static.packer_detected:
        tips.append("样本已加壳，建议在隔离环境脱壳后再进行代码级逆向分析。")
    if dynamic and any(f.is_c2 for f in dynamic.network_flows):
        tips.append("针对捕获的 C2 域名/IP 在边界设备上配置阻断策略。")
    if dynamic and (dynamic.evasion_events or dynamic.anti_analysis_detected):
        tips.append("样本存在反分析行为，需增强沙箱环境的虚拟化痕迹隐藏能力以提升触发率。")
    if static and any(i.ioc_type == "registry" for i in sample.iocs):
        tips.append("检查并清理样本写入的自启动注册表项与落地文件。")
    tips.append("持续监控样本家族关联样本，关注同源变种。")
    return tips


def render_html(db: Session, sample: models.Sample) -> str:
    context = build_context(db, sample)
    template = _env.get_template("report.html")
    return template.render(**context)


def render_pdf(db: Session, sample: models.Sample) -> bytes:
    """使用 ReportLab 直接生成 PDF（内置中文字体，Windows/Linux 通用）。"""
    context = build_context(db, sample)
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.cidfonts import UnicodeCIDFont
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
    base = getSampleStyleSheet()
    font = "STSong-Light"
    h1 = ParagraphStyle("h1", parent=base["Title"], fontName=font, fontSize=18, leading=24)
    h2 = ParagraphStyle("h2", parent=base["Heading2"], fontName=font, fontSize=13, leading=18, spaceBefore=10)
    body = ParagraphStyle("body", parent=base["BodyText"], fontName=font, fontSize=9, leading=13)
    cell = ParagraphStyle("cell", parent=body, fontSize=8, leading=11)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=18 * mm, bottomMargin=18 * mm)
    story = [Paragraph(f"{settings.APP_NAME} 安全分析报告", h1), Spacer(1, 6)]

    def table(rows, widths=None):
        t = Table(rows, colWidths=widths)
        t.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, -1), font),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        return t

    s = sample
    story.append(Paragraph("一、样本基本信息", h2))
    story.append(table([
        ["文件名", s.original_filename, "文件类型", s.file_kind],
        ["大小(字节)", str(s.file_size), "危害等级", LEVEL_CN.get(s.threat_level, "未知")],
        ["风险评分", f"{s.risk_score}/100", "加壳", s.packer or "无"],
        ["MD5", s.md5, "SHA1", s.sha1 or ""],
        ["SHA256", s.sha256, "imphash", s.imphash or ""],
        ["SSDEEP", s.ssdeep or "", "数字签名", ("已签名" if s.is_signed else "未签名")],
    ], [24 * mm, 60 * mm, 24 * mm, 60 * mm]))

    st = context["static"]
    if st:
        story.append(Paragraph("二、静态分析", h2))
        compile_time = st.compile_timestamp.strftime("%Y-%m-%d %H:%M:%S") if st.compile_timestamp else "未知"
        story.append(table([
            ["入口点", st.entry_point or "", "编译时间", compile_time],
            ["镜像基址", st.image_base or "", "节区数", str(len(st.sections))],
            ["文件熵", f"{s.entropy:.2f}", "PDB 路径", st.pdb_path or "无"],
        ], [24 * mm, 60 * mm, 24 * mm, 60 * mm]))

        if st.sections:
            story.append(Paragraph("节区表", body))
            rows = [["名称", "虚拟地址", "虚拟大小", "原始大小", "熵", "属性", "可疑"]]
            for sec in context["sections"]:
                rows.append([
                    sec.name, hex(sec.virtual_address), str(sec.virtual_size),
                    str(sec.raw_size), f"{sec.entropy:.2f}", "/".join(sec.flags or []),
                    "是" if sec.is_suspicious else "",
                ])
            story.append(table(rows))

        if context["features"]:
            story.append(Paragraph("可疑特征", body))
            rows = [["特征", "严重级别", "说明"]]
            for f in context["features"][:40]:
                rows.append([f.get("name", ""), SEVERITY_CN.get(f.get("severity"), f.get("severity")), Paragraph(f.get("description", ""), cell)])
            story.append(table(rows, [40 * mm, 20 * mm, 108 * mm]))

        if context["yara_matches"]:
            story.append(Paragraph("YARA 命中", body))
            rows = [["规则", "命名空间", "描述"]]
            for m in context["yara_matches"]:
                rows.append([m.rule_name, m.namespace or "", Paragraph(m.description or "", cell)])
            story.append(table(rows, [55 * mm, 30 * mm, 83 * mm]))

    dy = context["dynamic"]
    if dy:
        story.append(Paragraph("三、动态沙箱分析", h2))
        story.append(table([
            ["沙箱驱动", dy.sandbox_driver, "虚拟机", dy.vm_name or ""],
            ["运行时长(秒)", str(dy.duration_sec), "判定", LEVEL_CN.get(dy.verdict, dy.verdict)],
            ["反分析", "是" if dy.anti_analysis_detected else "否", "风险分", f"{dy.risk_score}/100"],
        ], [24 * mm, 60 * mm, 24 * mm, 60 * mm]))
        if context["attck"]:
            story.append(Paragraph("ATT&CK 技术映射", body))
            rows = [["技术编号", "技术名称", "战术"]]
            for t in context["attck"]:
                rows.append([t.get("id", ""), t.get("name", ""), t.get("tactic", "")])
            story.append(table(rows, [30 * mm, 80 * mm, 58 * mm]))
        if context["network_flows"]:
            story.append(Paragraph("网络行为", body))
            rows = [["协议", "目的地址", "域名/SNI", "C2"]]
            for f in context["network_flows"][:40]:
                rows.append([f.protocol, f"{f.dst_ip or ''}:{f.dst_port or ''}", f.domain or f.tls_sni or f.dns_query or "", "是" if f.is_c2 else ""])
            story.append(table(rows, [20 * mm, 50 * mm, 78 * mm, 20 * mm]))

    story.append(Paragraph("四、IOC 威胁指标", h2))
    if context["iocs"]:
        rows = [["类型", "值", "来源", "威胁分"]]
        for i in context["iocs"][:80]:
            rows.append([i.ioc_type, Paragraph(i.value[:300], cell), i.source, str(i.threat_score)])
        story.append(table(rows, [22 * mm, 108 * mm, 18 * mm, 20 * mm]))
    else:
        story.append(Paragraph("未提取到 IOC。", body))

    story.append(Paragraph("五、分析结论", h2))
    story.append(Paragraph(context["conclusion"], body))
    story.append(Paragraph("六、处置建议", h2))
    for tip in context["suggestions"]:
        story.append(Paragraph(f"• {tip}", body))

    doc.build(story)
    return buf.getvalue()


def generate_report(db: Session, sample: models.Sample, fmt: str = "html", *, user=None) -> models.Report:
    """生成报告文件并落库。"""
    report_id = str(uuid.uuid4())
    if fmt == "pdf":
        content = render_pdf(db, sample)
        data = content
        suffix = "pdf"
    elif fmt == "json":
        import json

        content = build_context(db, sample)
        serializable = {
            "sample": {
                "id": sample.id, "filename": sample.original_filename, "sha256": sample.sha256,
                "md5": sample.md5, "threat_level": sample.threat_level, "risk_score": sample.risk_score,
            },
            "iocs": [
                {"type": i.ioc_type, "value": i.value, "score": i.threat_score, "source": i.source}
                for i in sample.iocs
            ],
        }
        data = json.dumps(serializable, ensure_ascii=False, indent=2).encode("utf-8")
        suffix = "json"
    else:
        data = render_html(db, sample).encode("utf-8")
        suffix = "html"

    out_path = settings.REPORT_DIR / f"{report_id}.{suffix}"
    out_path.write_bytes(data)

    report = models.Report(
        id=report_id,
        sample_id=sample.id,
        title=f"{sample.original_filename} 安全分析报告",
        format=fmt,
        file_path=str(out_path),
        file_size=len(data),
        generated_by=getattr(user, "id", None),
        summary={"risk_level": sample.threat_level, "risk_score": sample.risk_score},
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    logger.info("报告已生成：%s (%s)", report.id, fmt)
    return report
