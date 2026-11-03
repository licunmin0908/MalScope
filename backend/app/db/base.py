"""SQLAlchemy 声明式基类与公共列/枚举。"""

from __future__ import annotations

import datetime as dt
import enum

from sqlalchemy import DateTime, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """所有 ORM 模型的基类。"""


class TimestampMixin:
    """统一的创建/更新时间戳。"""

    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False, index=True
    )
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now(), nullable=False
    )


# ================= 业务枚举 =================

class ThreatLevel(str, enum.Enum):
    """样本危害等级。"""

    MALICIOUS = "malicious"  # 恶意
    SUSPICIOUS = "suspicious"  # 可疑
    CLEAN = "clean"  # 无害
    UNKNOWN = "unknown"  # 未知


class FileKind(str, enum.Enum):
    """样本文件大类。"""

    PE = "pe"
    ELF = "elf"
    OFFICE = "office"
    PDF = "pdf"
    SCRIPT = "script"
    ARCHIVE = "archive"
    MACHO = "macho"
    UNKNOWN = "unknown"


class TaskType(str, enum.Enum):
    STATIC = "static"
    DYNAMIC = "dynamic"
    FULL = "full"


class TaskStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class IOCType(str, enum.Enum):
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SSDEEP = "ssdeep"
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    C2 = "c2"
    EMAIL = "email"
    REGISTRY = "registry"
    FILEPATH = "filepath"
    MUTEX = "mutex"
    USERAGENT = "useragent"
    CERTIFICATE = "certificate"
    CVE = "cve"
    YARA = "yara"


class BehaviorCategory(str, enum.Enum):
    """动态行为大类，用于 ATT&CK 映射与前端时间线分组。"""

    PROCESS = "process"
    FILE = "file"
    REGISTRY = "registry"
    NETWORK = "network"
    MEMORY = "memory"
    SYSTEM = "system"
    ANTIDEBUG = "antidebug"


class ExportFormat(str, enum.Enum):
    CSV = "csv"
    JSON = "json"
    STIX = "stix"
    OPENIOC = "openioc"
