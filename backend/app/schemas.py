"""API 数据传输对象（Pydantic v2）。"""

from __future__ import annotations

import datetime as dt
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ==================== 通用 ====================

class Page(BaseModel, Generic[T]):
    total: int
    items: list[T]


class Message(BaseModel):
    message: str


# ==================== 认证与用户 ====================

class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class PermissionOut(ORMModel):
    id: int
    code: str
    name: str
    module: str | None = None


class RoleOut(ORMModel):
    id: int
    name: str
    description: str | None = None
    permissions: list[PermissionOut] = []


class UserOut(ORMModel):
    id: int
    username: str
    email: str | None = None
    display_name: str | None = None
    is_active: bool
    is_superuser: bool
    last_login_at: dt.datetime | None = None
    roles: list[RoleOut] = []


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=6, max_length=128)
    email: str | None = None
    display_name: str | None = None
    role_names: list[str] = []


class UserUpdate(BaseModel):
    email: str | None = None
    display_name: str | None = None
    is_active: bool | None = None
    password: str | None = None
    role_names: list[str] | None = None


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserOut


# ==================== 样本 ====================

class SampleOut(ORMModel):
    id: str
    original_filename: str
    file_size: int
    file_kind: str
    mime_type: str | None = None
    md5: str
    sha1: str
    sha256: str
    ssdeep: str | None = None
    imphash: str | None = None
    crc32: str | None = None
    entropy: float
    is_pe: bool
    is_signed: bool
    signature_subject: str | None = None
    packer: str | None = None
    threat_level: str
    risk_score: int
    family: str | None = None
    tags: list[Any] | None = None
    description: str | None = None
    upload_ip: str | None = None
    created_at: dt.datetime


class SampleDetail(SampleOut):
    mime_type: str | None = None


class SampleUpdate(BaseModel):
    family: str | None = None
    tags: list[str] | None = None
    description: str | None = None
    threat_level: str | None = None


# ==================== 分析任务 ====================

class TaskOut(ORMModel):
    id: str
    sample_id: str
    task_type: str
    status: str
    progress: int
    stage: str | None = None
    error_message: str | None = None
    started_at: dt.datetime | None = None
    finished_at: dt.datetime | None = None
    duration_ms: int | None = None
    created_at: dt.datetime


class AnalysisRequest(BaseModel):
    task_type: str = Field(default="static", pattern="^(static|dynamic|full)$")


class SectionOut(ORMModel):
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    entropy: float
    flags: list[Any] | None = None
    is_rwx: bool
    is_suspicious: bool
    suspicion_reason: str | None = None


class ImportOut(ORMModel):
    dll: str
    function: str
    risk_category: str | None = None
    risk_level: str | None = None
    description: str | None = None


class StringOut(ORMModel):
    value: str
    encoding: str
    offset: int
    category: str
    risk_level: str
    is_whitelisted: bool


class YaraMatchOut(ORMModel):
    rule_name: str
    namespace: str | None = None
    description: str | None = None
    severity: str | None = None
    tags: list[Any] | None = None
    matched_strings: list[Any] | None = None


class StaticResultOut(ORMModel):
    id: int
    file_kind: str
    file_type_desc: str | None = None
    entry_point: str | None = None
    image_base: str | None = None
    compile_timestamp: dt.datetime | None = None
    pdb_path: str | None = None
    packer_detected: bool
    packer_name: str | None = None
    packer_confidence: int
    risk_score: int
    risk_level: str
    dos_header: dict | None = None
    nt_headers: dict | None = None
    optional_header: dict | None = None
    data_directories: list | None = None
    version_info: dict | None = None
    signature: dict | None = None
    suspicious_features: list | None = None
    api_risk_summary: dict | None = None
    behavior_hints: list | None = None
    resources: list | None = None
    created_at: dt.datetime


class StaticFull(StaticResultOut):
    sections: list[SectionOut] = []
    imports: list[ImportOut] = []
    exports: list[dict] = []
    strings: list[StringOut] = []
    yara_matches: list[YaraMatchOut] = []


class ProcessOut(ORMModel):
    pid: int
    ppid: int | None = None
    name: str
    path: str | None = None
    cmdline: str | None = None
    user: str | None = None
    integrity_level: str | None = None
    is_injected: bool
    is_elevated: bool
    child_count: int


class EventOut(ORMModel):
    timestamp: dt.datetime
    category: str
    action: str
    object: str | None = None
    result: str | None = None
    pid: int | None = None
    process_name: str | None = None
    severity: str
    attck_technique_id: str | None = None
    attck_technique: str | None = None
    detail: dict | None = None


class NetworkFlowOut(ORMModel):
    timestamp: dt.datetime
    protocol: str
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    domain: str | None = None
    url: str | None = None
    http_method: str | None = None
    user_agent: str | None = None
    tls_sni: str | None = None
    dns_query: str | None = None
    is_c2: bool
    c2_confidence: int
    c2_reason: str | None = None


class FileEventOut(ORMModel):
    timestamp: dt.datetime
    action: str
    path: str
    new_path: str | None = None
    size: int | None = None
    is_autorun: bool
    is_ransomware: bool
    is_dropped: bool


class RegistryEventOut(ORMModel):
    timestamp: dt.datetime
    action: str
    key_path: str
    value_name: str | None = None
    value_data: str | None = None
    is_persistence: bool
    is_hijack: bool
    is_defense_evasion: bool


class DynamicResultOut(ORMModel):
    id: int
    sandbox_driver: str
    vm_name: str | None = None
    snapshot: str | None = None
    guest_os: str | None = None
    duration_sec: int
    status: str
    verdict: str
    risk_score: int
    behavior_summary: dict | None = None
    attck_techniques: list | None = None
    evasion_events: list | None = None
    anti_analysis_detected: bool
    dropped_files: list | None = None
    created_at: dt.datetime


class DynamicFull(DynamicResultOut):
    processes: list[ProcessOut] = []
    events: list[EventOut] = []
    network_flows: list[NetworkFlowOut] = []
    file_events: list[FileEventOut] = []
    registry_events: list[RegistryEventOut] = []


# ==================== IOC ====================

class IoCOut(ORMModel):
    id: int
    sample_id: str | None = None
    ioc_type: str
    value: str
    context: str | None = None
    confidence: int
    threat_score: int
    source: str
    is_whitelisted: bool
    tags: list[Any] | None = None
    first_seen: dt.datetime | None = None


class ExportRequest(BaseModel):
    format: str = Field(default="json", pattern="^(csv|json|stix|openioc)$")
    sample_id: str | None = None
    ioc_type: str | None = None
    min_score: int = 0


class MispPushRequest(BaseModel):
    sample_id: str
    event_info: str | None = None


# ==================== 报告 ====================

class ReportOut(ORMModel):
    id: str
    sample_id: str | None = None
    title: str
    format: str
    file_size: int
    summary: dict | None = None
    created_at: dt.datetime


# ==================== 规则 ====================

class YaraRuleOut(ORMModel):
    id: int
    name: str
    description: str | None = None
    author: str | None = None
    severity: str
    tags: list[Any] | None = None
    is_builtin: bool
    is_enabled: bool
    created_at: dt.datetime


class YaraRuleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    rules_text: str = Field(min_length=1)
    description: str | None = None
    author: str | None = None
    severity: str = Field(default="medium", pattern="^(info|low|medium|high|critical)$")
    tags: list[str] = []
    is_enabled: bool = True


class PackerSignatureOut(ORMModel):
    id: int
    name: str
    category: str
    section_names: list[Any] | None = None
    description: str | None = None
    severity: str


# ==================== 审计与仪表盘 ====================

class AuditOut(ORMModel):
    id: int
    username: str | None = None
    action: str
    resource_type: str | None = None
    resource_id: str | None = None
    result: str
    ip: str | None = None
    detail: dict | None = None
    created_at: dt.datetime


class DashboardStats(BaseModel):
    total_samples: int
    malicious_samples: int
    suspicious_samples: int
    clean_samples: int
    total_tasks: int
    running_tasks: int
    total_iocs: int
    c2_iocs: int
    by_file_kind: dict[str, int]
    by_threat_level: dict[str, int]
    recent_samples: list[SampleOut]
    top_iocs: list[IoCOut]
    attck_distribution: list[dict]


Token.model_rebuild()
UserOut.model_rebuild()
