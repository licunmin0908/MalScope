"""全局配置中心。

所有可调参数集中于此，支持通过环境变量或 backend/.env 覆盖。
路径统一以 backend/ 为基准目录，避免不同启动工作目录导致的路径漂移。
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/ 目录（config.py -> core -> app -> backend）
BACKEND_DIR = Path(__file__).resolve().parents[2]
# 项目根目录（含 backend/frontend/sandbox/docs）
PROJECT_DIR = BACKEND_DIR.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(BACKEND_DIR / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # ================= 应用 =================
    APP_NAME: str = "MalScope 恶意软件样本智能分析平台"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True
    API_PREFIX: str = "/api/v1"
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    # ================= 数据库 =================
    # 默认 SQLite 保证开箱可运行；生产切换 MySQL 8.0
    DATABASE_URL: str = f"sqlite:///{(BACKEND_DIR / 'data' / 'malscope.db').as_posix()}"
    DB_ECHO: bool = False
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20

    # ================= Redis / 任务队列 =================
    REDIS_URL: str = "redis://127.0.0.1:6379/0"
    USE_CELERY: bool = False

    # ================= 安全 =================
    SECRET_KEY: str = "malscope-dev-secret-key-change-me-please-32bytes-min"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 720
    # AES-256-GCM 样本加密主密钥（base64），留空则由 SECRET_KEY 派生
    AES_MASTER_KEY: str = ""

    # ================= 上传与存储 =================
    MAX_UPLOAD_SIZE: int = 100 * 1024 * 1024  # 单文件 100MB
    MAX_EXTRACTED_SIZE: int = 500 * 1024 * 1024  # 解压后上限 500MB（防压缩炸弹）
    MAX_ARCHIVE_ENTRIES: int = 1000  # 压缩包最大条目数
    STORAGE_DIR: Path = BACKEND_DIR / "storage"

    # ================= 沙箱 =================
    SANDBOX_DRIVER: str = "mock"  # virtualbox / libvirt / mock
    SANDBOX_VM_NAME: str = "MALSCOPE_WIN10"
    SANDBOX_SNAPSHOT: str = "clean_base"
    SANDBOX_TIMEOUT: int = 120
    SANDBOX_DISABLE_NETWORK: bool = True
    SANDBOX_GUEST_USER: str = "analyst"
    SANDBOX_GUEST_PASSWORD: str = "malscope"

    # ================= 威胁情报 =================
    VIRUSTOTAL_API_KEY: str = ""
    MISP_URL: str = ""
    MISP_API_KEY: str = ""
    # 内网/本地白名单网段（用于降噪，避免把本地地址当 C2）
    PRIVATE_NETS: list[str] = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
    ]

    # ================= 派生路径 =================
    @property
    def SAMPLE_DIR(self) -> Path:
        """加密样本落盘目录。"""
        return self.STORAGE_DIR / "samples"

    @property
    def QUARANTINE_DIR(self) -> Path:
        """隔离/解包中间目录，仅沙箱与分析引擎可读。"""
        return self.STORAGE_DIR / "quarantine"

    @property
    def REPORT_DIR(self) -> Path:
        return self.STORAGE_DIR / "reports"

    @property
    def TMP_DIR(self) -> Path:
        return self.STORAGE_DIR / "tmp"

    @property
    def LOG_DIR(self) -> Path:
        return self.STORAGE_DIR / "logs"

    @property
    def YARA_RULE_DIR(self) -> Path:
        return BACKEND_DIR / "rules" / "yara"

    @property
    def PACKER_SIGNATURE_FILE(self) -> Path:
        return BACKEND_DIR / "rules" / "packer_signatures.json"

    @property
    def AES_KEY_BYTES(self) -> bytes:
        """返回 32 字节 AES-256 密钥。"""
        if self.AES_MASTER_KEY:
            key = base64.b64decode(self.AES_MASTER_KEY)
            if len(key) != 32:
                raise ValueError("AES_MASTER_KEY 必须是 base64 编码的 32 字节密钥")
            return key
        # 由 SECRET_KEY 确定性派生，保证重启后仍能解密历史样本
        return hashlib.sha256(self.SECRET_KEY.encode("utf-8")).digest()

    def ensure_dirs(self) -> None:
        """确保所有运行时目录存在。"""
        for d in (
            self.STORAGE_DIR,
            self.SAMPLE_DIR,
            self.QUARANTINE_DIR,
            self.REPORT_DIR,
            self.TMP_DIR,
            self.LOG_DIR,
            self.YARA_RULE_DIR,
            BACKEND_DIR / "data",
        ):
            d.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.ensure_dirs()
    return settings


settings = get_settings()

# 便于首次部署时生成随机密钥
def generate_secret() -> str:
    return secrets.token_urlsafe(48)
