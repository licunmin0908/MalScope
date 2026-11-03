"""MalScope 数据模型（SQLAlchemy 2.0）。

设计原则：
- 样本、分析任务、静态结果、动态行为、IOC、报告、审计各自独立成表；
- 高频检索字段（哈希、等级、时间、类型）建索引；
- 结构化但异构的分析明细使用 JSON 列，兼顾可读性与跨库（SQLite/MySQL）兼容；
- 行为事件按“时间—进程—对象—动作—结果”五元组建模，便于时间线回放与 ATT&CK 映射。
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin

# ==================== RBAC 关联表 ====================

user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
)

role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column("role_id", ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    Column("permission_id", ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True),
)


# ==================== 权限模块 ====================

class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    email: Mapped[str | None] = mapped_column(String(128), unique=True, nullable=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(64))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_login_at: Mapped[dt.datetime | None] = mapped_column(DateTime)
    last_login_ip: Mapped[str | None] = mapped_column(String(64))

    roles: Mapped[list["Role"]] = relationship(
        secondary=user_roles, back_populates="users", lazy="selectin"
    )
    samples: Mapped[list["Sample"]] = relationship(back_populates="uploader")

    def has_permission(self, code: str) -> bool:
        if self.is_superuser:
            return True
        return any(code in {p.code for p in role.permissions} for role in self.roles)


class Role(Base, TimestampMixin):
    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(255))

    users: Mapped[list[User]] = relationship(secondary=user_roles, back_populates="roles")
    permissions: Mapped[list["Permission"]] = relationship(
        secondary=role_permissions, back_populates="roles", lazy="selectin"
    )


class Permission(Base, TimestampMixin):
    __tablename__ = "permissions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    code: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(String(255))
    module: Mapped[str | None] = mapped_column(String(64))

    roles: Mapped[list[Role]] = relationship(
        secondary=role_permissions, back_populates="permissions"
    )


# ==================== 样本库 ====================

class Sample(Base, TimestampMixin):
    __tablename__ = "samples"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)  # UUID
    original_filename: Mapped[str] = mapped_column(String(512), nullable=False)
    stored_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    file_kind: Mapped[str] = mapped_column(String(16), default="unknown", index=True)
    mime_type: Mapped[str | None] = mapped_column(String(128))

    # 哈希指纹
    md5: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    sha1: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    ssdeep: Mapped[str | None] = mapped_column(String(255))
    imphash: Mapped[str | None] = mapped_column(String(32), index=True)
    crc32: Mapped[str | None] = mapped_column(String(8))

    # 静态摘要
    entropy: Mapped[float] = mapped_column(Float, default=0.0)
    is_pe: Mapped[bool] = mapped_column(Boolean, default=False)
    is_signed: Mapped[bool] = mapped_column(Boolean, default=False)
    signature_subject: Mapped[str | None] = mapped_column(String(512))
    packer: Mapped[str | None] = mapped_column(String(64))

    # 研判
    threat_level: Mapped[str] = mapped_column(String(16), default="unknown", index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    family: Mapped[str | None] = mapped_column(String(128), index=True)
    tags: Mapped[list | None] = mapped_column(JSON, default=list)
    description: Mapped[str | None] = mapped_column(Text)

    # 存储（样本全程加密落盘）
    storage_path: Mapped[str] = mapped_column(String(512), nullable=False)
    aes_nonce: Mapped[str | None] = mapped_column(String(64))
    is_encrypted: Mapped[bool] = mapped_column(Boolean, default=True)

    uploader_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    upload_ip: Mapped[str | None] = mapped_column(String(64))

    uploader: Mapped[User | None] = relationship(back_populates="samples")
    tasks: Mapped[list["AnalysisTask"]] = relationship(
        back_populates="sample", cascade="all, delete-orphan"
    )
    static_results: Mapped[list["StaticAnalysis"]] = relationship(
        back_populates="sample", cascade="all, delete-orphan"
    )
    dynamic_results: Mapped[list["DynamicAnalysis"]] = relationship(
        back_populates="sample", cascade="all, delete-orphan"
    )
    iocs: Mapped[list["IOC"]] = relationship(back_populates="sample", cascade="all, delete-orphan")
    reports: Mapped[list["Report"]] = relationship(
        back_populates="sample", cascade="all, delete-orphan"
    )

    __table_args__ = (Index("ix_samples_level_score", "threat_level", "risk_score"),)


# ==================== 分析任务 ====================

class AnalysisTask(Base, TimestampMixin):
    __tablename__ = "analysis_tasks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    sample_id: Mapped[str] = mapped_column(
        ForeignKey("samples.id", ondelete="CASCADE"), index=True, nullable=False
    )
    task_type: Mapped[str] = mapped_column(String(16), default="static", index=True)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    stage: Mapped[str | None] = mapped_column(String(64))
    error_message: Mapped[str | None] = mapped_column(Text)

    celery_task_id: Mapped[str | None] = mapped_column(String(64), index=True)
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime)
    duration_ms: Mapped[int | None] = mapped_column(Integer)

    result_summary: Mapped[dict | None] = mapped_column(JSON)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    sample: Mapped[Sample] = relationship(back_populates="tasks")
    static_result: Mapped["StaticAnalysis | None"] = relationship(
        back_populates="task", uselist=False
    )
    dynamic_result: Mapped["DynamicAnalysis | None"] = relationship(
        back_populates="task", uselist=False
    )


# ==================== 静态分析结果 ====================

class StaticAnalysis(Base, TimestampMixin):
    __tablename__ = "static_analysis"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sample_id: Mapped[str] = mapped_column(
        ForeignKey("samples.id", ondelete="CASCADE"), index=True, nullable=False
    )
    task_id: Mapped[str | None] = mapped_column(
        ForeignKey("analysis_tasks.id", ondelete="CASCADE"), unique=True
    )

    file_kind: Mapped[str] = mapped_column(String(16), default="unknown")
    file_type_desc: Mapped[str | None] = mapped_column(String(255))

    # PE 头部（原文 JSON，供前端逐字段展示）
    dos_header: Mapped[dict | None] = mapped_column(JSON)
    nt_headers: Mapped[dict | None] = mapped_column(JSON)
    optional_header: Mapped[dict | None] = mapped_column(JSON)
    data_directories: Mapped[dict | None] = mapped_column(JSON)
    entry_point: Mapped[str | None] = mapped_column(String(64))
    image_base: Mapped[str | None] = mapped_column(String(64))
    compile_timestamp: Mapped[dt.datetime | None] = mapped_column(DateTime)
    compile_timestamp_raw: Mapped[int | None] = mapped_column(BigInteger)
    pdb_path: Mapped[str | None] = mapped_column(String(512))
    rich_header: Mapped[dict | None] = mapped_column(JSON)

    # 加壳与异常
    packer_detected: Mapped[bool] = mapped_column(Boolean, default=False)
    packer_name: Mapped[str | None] = mapped_column(String(64))
    packer_confidence: Mapped[int] = mapped_column(Integer, default=0)

    # 资源与签名
    resources: Mapped[list | None] = mapped_column(JSON)
    version_info: Mapped[dict | None] = mapped_column(JSON)
    signature: Mapped[dict | None] = mapped_column(JSON)

    # 特征与评分
    suspicious_features: Mapped[list | None] = mapped_column(JSON)
    api_risk_summary: Mapped[dict | None] = mapped_column(JSON)
    behavior_hints: Mapped[list | None] = mapped_column(JSON)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_level: Mapped[str] = mapped_column(String(16), default="unknown")

    raw_result: Mapped[dict | None] = mapped_column(JSON)

    sample: Mapped[Sample] = relationship(back_populates="static_results")
    task: Mapped[AnalysisTask | None] = relationship(back_populates="static_result")
    sections: Mapped[list["Section"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan", lazy="selectin"
    )
    imports: Mapped[list["ImportEntry"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    exports: Mapped[list["ExportEntry"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    strings: Mapped[list["ExtractedString"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    yara_matches: Mapped[list["YaraMatch"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )


class Section(Base):
    """PE 节区。"""

    __tablename__ = "pe_sections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("static_analysis.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(16), index=True)
    virtual_address: Mapped[int] = mapped_column(BigInteger, default=0)
    virtual_size: Mapped[int] = mapped_column(BigInteger, default=0)
    raw_offset: Mapped[int] = mapped_column(BigInteger, default=0)
    raw_size: Mapped[int] = mapped_column(BigInteger, default=0)
    entropy: Mapped[float] = mapped_column(Float, default=0.0)
    md5: Mapped[str | None] = mapped_column(String(32))
    sha256: Mapped[str | None] = mapped_column(String(64))
    characteristics: Mapped[int] = mapped_column(BigInteger, default=0)
    flags: Mapped[list | None] = mapped_column(JSON)  # R/W/X 等
    is_executable: Mapped[bool] = mapped_column(Boolean, default=False)
    is_writable: Mapped[bool] = mapped_column(Boolean, default=False)
    is_readable: Mapped[bool] = mapped_column(Boolean, default=False)
    is_rwx: Mapped[bool] = mapped_column(Boolean, default=False)
    is_suspicious: Mapped[bool] = mapped_column(Boolean, default=False)
    suspicion_reason: Mapped[str | None] = mapped_column(String(255))

    analysis: Mapped[StaticAnalysis] = relationship(back_populates="sections")


class ImportEntry(Base):
    """导入函数（含风险分类）。"""

    __tablename__ = "pe_imports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("static_analysis.id", ondelete="CASCADE"), index=True, nullable=False
    )
    dll: Mapped[str] = mapped_column(String(128), index=True)
    function: Mapped[str] = mapped_column(String(128), index=True)
    ordinal: Mapped[int | None] = mapped_column(Integer)
    risk_category: Mapped[str | None] = mapped_column(String(64), index=True)
    risk_level: Mapped[str | None] = mapped_column(String(16))
    description: Mapped[str | None] = mapped_column(String(255))
    references: Mapped[list | None] = mapped_column(JSON)  # 相关 ATT&CK / 说明

    analysis: Mapped[StaticAnalysis] = relationship(back_populates="imports")


class ExportEntry(Base):
    __tablename__ = "pe_exports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("static_analysis.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), index=True)
    ordinal: Mapped[int | None] = mapped_column(Integer)
    address: Mapped[str | None] = mapped_column(String(32))
    forwarder: Mapped[str | None] = mapped_column(String(255))

    analysis: Mapped[StaticAnalysis] = relationship(back_populates="exports")


class ExtractedString(Base):
    """提取出的字符串及其分类。"""

    __tablename__ = "extracted_strings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("static_analysis.id", ondelete="CASCADE"), index=True, nullable=False
    )
    value: Mapped[str] = mapped_column(Text, nullable=False)
    encoding: Mapped[str] = mapped_column(String(16), default="ascii")  # ascii / utf-16le
    offset: Mapped[int] = mapped_column(BigInteger, default=0)
    category: Mapped[str] = mapped_column(String(32), default="text", index=True)
    risk_level: Mapped[str] = mapped_column(String(16), default="info", index=True)
    is_whitelisted: Mapped[bool] = mapped_column(Boolean, default=False)

    analysis: Mapped[StaticAnalysis] = relationship(back_populates="strings")


class YaraMatch(Base):
    __tablename__ = "yara_matches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("static_analysis.id", ondelete="CASCADE"), index=True, nullable=False
    )
    rule_name: Mapped[str] = mapped_column(String(128), index=True)
    namespace: Mapped[str | None] = mapped_column(String(128))
    description: Mapped[str | None] = mapped_column(String(512))
    severity: Mapped[str | None] = mapped_column(String(16))
    tags: Mapped[list | None] = mapped_column(JSON)
    matched_strings: Mapped[list | None] = mapped_column(JSON)  # [{identifier, offset, data}]

    analysis: Mapped[StaticAnalysis] = relationship(back_populates="yara_matches")


# ==================== 动态沙箱结果 ====================

class DynamicAnalysis(Base, TimestampMixin):
    __tablename__ = "dynamic_analysis"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sample_id: Mapped[str] = mapped_column(
        ForeignKey("samples.id", ondelete="CASCADE"), index=True, nullable=False
    )
    task_id: Mapped[str | None] = mapped_column(
        ForeignKey("analysis_tasks.id", ondelete="CASCADE"), unique=True
    )

    sandbox_driver: Mapped[str] = mapped_column(String(32), default="mock")
    vm_name: Mapped[str | None] = mapped_column(String(64))
    snapshot: Mapped[str | None] = mapped_column(String(64))
    guest_os: Mapped[str | None] = mapped_column(String(128))
    executed_at: Mapped[dt.datetime | None] = mapped_column(DateTime)
    duration_sec: Mapped[int] = mapped_column(Integer, default=0)

    status: Mapped[str] = mapped_column(String(16), default="running")
    verdict: Mapped[str] = mapped_column(String(16), default="unknown")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)

    # 行为摘要与 ATT&CK
    behavior_summary: Mapped[dict | None] = mapped_column(JSON)
    attck_techniques: Mapped[list | None] = mapped_column(JSON)
    evasion_events: Mapped[list | None] = mapped_column(JSON)
    anti_analysis_detected: Mapped[bool] = mapped_column(Boolean, default=False)
    dropped_files: Mapped[list | None] = mapped_column(JSON)
    raw_log_path: Mapped[str | None] = mapped_column(String(512))

    sample: Mapped[Sample] = relationship(back_populates="dynamic_results")
    task: Mapped[AnalysisTask | None] = relationship(back_populates="dynamic_result")

    processes: Mapped[list["ProcessNode"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan", lazy="selectin"
    )
    events: Mapped[list["BehaviorEvent"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    network_flows: Mapped[list["NetworkFlow"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    file_events: Mapped[list["FileEvent"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    registry_events: Mapped[list["RegistryEvent"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )


class ProcessNode(Base):
    """进程树节点。"""

    __tablename__ = "process_nodes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    dynamic_id: Mapped[int] = mapped_column(
        ForeignKey("dynamic_analysis.id", ondelete="CASCADE"), index=True, nullable=False
    )
    pid: Mapped[int] = mapped_column(Integer, index=True)
    ppid: Mapped[int | None] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String(255))
    path: Mapped[str | None] = mapped_column(String(512))
    cmdline: Mapped[str | None] = mapped_column(Text)
    user: Mapped[str | None] = mapped_column(String(64))
    integrity_level: Mapped[str | None] = mapped_column(String(32))
    start_time: Mapped[dt.datetime | None] = mapped_column(DateTime)
    end_time: Mapped[dt.datetime | None] = mapped_column(DateTime)
    is_injected: Mapped[bool] = mapped_column(Boolean, default=False)
    is_elevated: Mapped[bool] = mapped_column(Boolean, default=False)
    modules: Mapped[list | None] = mapped_column(JSON)
    child_count: Mapped[int] = mapped_column(Integer, default=0)

    analysis: Mapped[DynamicAnalysis] = relationship(back_populates="processes")


class BehaviorEvent(Base):
    """通用行为事件：时间—进程—对象—动作—结果。"""

    __tablename__ = "behavior_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    dynamic_id: Mapped[int] = mapped_column(
        ForeignKey("dynamic_analysis.id", ondelete="CASCADE"), index=True, nullable=False
    )
    timestamp: Mapped[dt.datetime] = mapped_column(DateTime, index=True)
    category: Mapped[str] = mapped_column(String(32), index=True)  # process/file/registry/network/memory/antidebug
    action: Mapped[str] = mapped_column(String(128))
    object: Mapped[str | None] = mapped_column(Text)
    result: Mapped[str | None] = mapped_column(String(64))
    pid: Mapped[int | None] = mapped_column(Integer, index=True)
    process_name: Mapped[str | None] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16), default="info")
    attck_technique_id: Mapped[str | None] = mapped_column(String(16), index=True)
    attck_technique: Mapped[str | None] = mapped_column(String(128))
    detail: Mapped[dict | None] = mapped_column(JSON)

    analysis: Mapped[DynamicAnalysis] = relationship(back_populates="events")

    __table_args__ = (Index("ix_behavior_dyn_time", "dynamic_id", "timestamp"),)


class NetworkFlow(Base):
    """网络连接 / DNS / HTTP / TLS 记录。"""

    __tablename__ = "network_flows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    dynamic_id: Mapped[int] = mapped_column(
        ForeignKey("dynamic_analysis.id", ondelete="CASCADE"), index=True, nullable=False
    )
    timestamp: Mapped[dt.datetime] = mapped_column(DateTime, index=True)
    protocol: Mapped[str] = mapped_column(String(16), index=True)  # TCP/UDP/DNS/HTTP/TLS/SMTP
    src_ip: Mapped[str | None] = mapped_column(String(64))
    src_port: Mapped[int | None] = mapped_column(Integer)
    dst_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    dst_port: Mapped[int | None] = mapped_column(Integer)
    domain: Mapped[str | None] = mapped_column(String(255), index=True)
    url: Mapped[str | None] = mapped_column(Text)
    http_method: Mapped[str | None] = mapped_column(String(16))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    tls_sni: Mapped[str | None] = mapped_column(String(255))
    dns_query: Mapped[str | None] = mapped_column(String(255))
    direction: Mapped[str | None] = mapped_column(String(16))
    is_c2: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    c2_confidence: Mapped[int] = mapped_column(Integer, default=0)
    c2_reason: Mapped[str | None] = mapped_column(String(255))
    raw: Mapped[dict | None] = mapped_column(JSON)

    analysis: Mapped[DynamicAnalysis] = relationship(back_populates="network_flows")


class FileEvent(Base):
    __tablename__ = "file_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    dynamic_id: Mapped[int] = mapped_column(
        ForeignKey("dynamic_analysis.id", ondelete="CASCADE"), index=True, nullable=False
    )
    timestamp: Mapped[dt.datetime] = mapped_column(DateTime, index=True)
    action: Mapped[str] = mapped_column(String(32), index=True)  # create/write/delete/rename/read
    path: Mapped[str] = mapped_column(String(1024), index=True)
    new_path: Mapped[str | None] = mapped_column(String(1024))
    pid: Mapped[int | None] = mapped_column(Integer)
    process_name: Mapped[str | None] = mapped_column(String(255))
    size: Mapped[int | None] = mapped_column(BigInteger)
    sha256: Mapped[str | None] = mapped_column(String(64))
    is_autorun: Mapped[bool] = mapped_column(Boolean, default=False)
    is_ransomware: Mapped[bool] = mapped_column(Boolean, default=False)
    is_dropped: Mapped[bool] = mapped_column(Boolean, default=False)

    analysis: Mapped[DynamicAnalysis] = relationship(back_populates="file_events")


class RegistryEvent(Base):
    __tablename__ = "registry_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    dynamic_id: Mapped[int] = mapped_column(
        ForeignKey("dynamic_analysis.id", ondelete="CASCADE"), index=True, nullable=False
    )
    timestamp: Mapped[dt.datetime] = mapped_column(DateTime, index=True)
    action: Mapped[str] = mapped_column(String(32), index=True)  # create/set/delete/query
    key_path: Mapped[str] = mapped_column(String(1024), index=True)
    value_name: Mapped[str | None] = mapped_column(String(255))
    value_data: Mapped[str | None] = mapped_column(Text)
    pid: Mapped[int | None] = mapped_column(Integer)
    process_name: Mapped[str | None] = mapped_column(String(255))
    is_persistence: Mapped[bool] = mapped_column(Boolean, default=False)
    is_hijack: Mapped[bool] = mapped_column(Boolean, default=False)
    is_defense_evasion: Mapped[bool] = mapped_column(Boolean, default=False)

    analysis: Mapped[DynamicAnalysis] = relationship(back_populates="registry_events")


# ==================== 威胁情报 / IOC ====================

class IOC(Base, TimestampMixin):
    __tablename__ = "iocs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sample_id: Mapped[str | None] = mapped_column(
        ForeignKey("samples.id", ondelete="CASCADE"), index=True
    )
    dynamic_id: Mapped[int | None] = mapped_column(
        ForeignKey("dynamic_analysis.id", ondelete="SET NULL"), index=True
    )
    ioc_type: Mapped[str] = mapped_column(String(16), index=True, nullable=False)
    value: Mapped[str] = mapped_column(String(2048), index=True, nullable=False)
    context: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    threat_score: Mapped[int] = mapped_column(Integer, default=0)
    source: Mapped[str] = mapped_column(String(16), default="static")  # static/dynamic/intel
    is_whitelisted: Mapped[bool] = mapped_column(Boolean, default=False)
    tags: Mapped[list | None] = mapped_column(JSON)
    first_seen: Mapped[dt.datetime | None] = mapped_column(DateTime)

    sample: Mapped[Sample | None] = relationship(back_populates="iocs")
    intel_records: Mapped[list["ThreatIntelRecord"]] = relationship(
        back_populates="ioc", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_ioc_value_type", "value", "ioc_type"),
        Index("ix_ioc_sample_type", "sample_id", "ioc_type"),
    )


class ThreatIntelRecord(Base, TimestampMixin):
    __tablename__ = "threat_intel_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ioc_id: Mapped[int] = mapped_column(
        ForeignKey("iocs.id", ondelete="CASCADE"), index=True, nullable=False
    )
    source: Mapped[str] = mapped_column(String(64))  # VirusTotal / MISP / 本地情报
    verdict: Mapped[str | None] = mapped_column(String(32))
    score: Mapped[int] = mapped_column(Integer, default=0)
    positives: Mapped[int | None] = mapped_column(Integer)
    total_engines: Mapped[int | None] = mapped_column(Integer)
    tags: Mapped[list | None] = mapped_column(JSON)
    raw: Mapped[dict | None] = mapped_column(JSON)
    fetched_at: Mapped[dt.datetime | None] = mapped_column(DateTime)

    ioc: Mapped[IOC] = relationship(back_populates="intel_records")


class Report(Base, TimestampMixin):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    sample_id: Mapped[str | None] = mapped_column(
        ForeignKey("samples.id", ondelete="CASCADE"), index=True
    )
    task_id: Mapped[str | None] = mapped_column(String(36))
    title: Mapped[str] = mapped_column(String(255))
    format: Mapped[str] = mapped_column(String(16), default="html")
    file_path: Mapped[str | None] = mapped_column(String(512))
    file_size: Mapped[int] = mapped_column(BigInteger, default=0)
    generated_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    summary: Mapped[dict | None] = mapped_column(JSON)

    sample: Mapped[Sample | None] = relationship(back_populates="reports")


# ==================== 审计 ====================

class AuditLog(Base, TimestampMixin):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    username: Mapped[str | None] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)  # upload/download/analyze/delete/login...
    resource_type: Mapped[str | None] = mapped_column(String(64))
    resource_id: Mapped[str | None] = mapped_column(String(64), index=True)
    result: Mapped[str] = mapped_column(String(16), default="success")
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    detail: Mapped[dict | None] = mapped_column(JSON)


# ==================== 规则库 ====================

class YaraRule(Base, TimestampMixin):
    __tablename__ = "yara_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(512))
    source: Mapped[str] = mapped_column(String(512), default="builtin")
    rules_text: Mapped[str] = mapped_column(Text)
    author: Mapped[str | None] = mapped_column(String(128))
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    tags: Mapped[list | None] = mapped_column(JSON)
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class PackerSignature(Base, TimestampMixin):
    __tablename__ = "packer_signatures"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    category: Mapped[str] = mapped_column(String(32), default="packer")
    section_names: Mapped[list | None] = mapped_column(JSON)
    entry_pattern: Mapped[str | None] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(16), default="medium")
