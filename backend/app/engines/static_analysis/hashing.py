"""哈希指纹计算。

- MD5 / SHA1 / SHA256：标准摘要，用于样本唯一标识与情报比对；
- CRC32：轻量校验；
- SSDEEP（模糊哈希/上下文触发分段哈希）：用于同源变种聚类，
  优先使用 ssdeep/pydeep 原生库，缺失时回退到内置纯 Python 实现；
- imphash：由导入表推导的指纹，用于识别同一构建环境/加壳工具产出的样本族。
"""

from __future__ import annotations

import hashlib
import zlib
from pathlib import Path

from app.core.logging import get_logger

logger = get_logger("static.hashing")

# 可选原生实现
try:  # pragma: no cover - 取决于运行环境
    import ssdeep as _ssdeep  # type: ignore

    _HAS_SSDEEP = True
except ImportError:  # pragma: no cover
    _ssdeep = None
    _HAS_SSDEEP = False

_CHUNK = 1024 * 1024

# ---------------- 纯 Python SSDEEP（spamsum）实现 ----------------
_HASH_PRIME = 0x01000193
_HASH_INIT = 0x28021967
_ROLLING_WINDOW = 7
_SPAMSUM_LENGTH = 64
_MIN_BLOCKSIZE = 3
_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


class _RollingHash:
    """spamsum 滚动哈希（窗口长度 7）。"""

    __slots__ = ("window", "h1", "h2", "h3", "n")

    def __init__(self) -> None:
        self.window = [0] * _ROLLING_WINDOW
        self.h1 = self.h2 = self.h3 = 0
        self.n = 0

    def update(self, c: int) -> None:
        self.h2 = (self.h2 - self.h1) & 0xFFFFFFFF
        self.h2 = (self.h2 + _ROLLING_WINDOW * c) & 0xFFFFFFFF
        self.h1 = (self.h1 + c) & 0xFFFFFFFF
        self.h1 = (self.h1 - self.window[self.n % _ROLLING_WINDOW]) & 0xFFFFFFFF
        self.window[self.n % _ROLLING_WINDOW] = c
        self.n += 1
        self.h3 = ((self.h3 << 5) & 0xFFFFFFFF) ^ c

    def digest(self) -> int:
        return (self.h1 + self.h2 + self.h3) & 0xFFFFFFFF

    def reset(self) -> None:
        self.window = [0] * _ROLLING_WINDOW
        self.h1 = self.h2 = self.h3 = 0
        self.n = 0


def _sum_hash(c: int, h: int) -> int:
    return ((h * _HASH_PRIME) & 0xFFFFFFFF) ^ c


def _spamsum(data: bytes, block_size: int) -> str:
    roll = _RollingHash()
    h = _HASH_INIT
    out: list[str] = []
    for c in data:
        roll.update(c)
        h = _sum_hash(c, h)
        if roll.digest() % block_size == block_size - 1:
            if len(out) < _SPAMSUM_LENGTH - 1:
                out.append(_B64[h % 64])
            roll.reset()
            h = _HASH_INIT
    out.append(_B64[h % 64])
    return "".join(out)


def fuzzy_hash(data: bytes) -> str:
    """计算 SSDEEP 模糊哈希，格式 ``blocksize:sig1:sig2``。"""
    if _HAS_SSDEEP:
        try:  # pragma: no cover
            return _ssdeep.hash(data)
        except Exception:  # noqa: BLE001 - 原生库异常时回退
            pass
    if not data:
        return "3::"
    block_size = _MIN_BLOCKSIZE
    while block_size * _SPAMSUM_LENGTH < len(data):
        block_size *= 2
    while True:
        sig1 = _spamsum(data, block_size)
        if len(sig1) >= _SPAMSUM_LENGTH - 1 and block_size < (1 << 31):
            block_size *= 2
            continue
        break
    sig2 = _spamsum(data, block_size * 2)
    return f"{block_size}:{sig1}:{sig2}"


def _lcs_length(a: str, b: str) -> int:
    if not a or not b:
        return 0
    prev = [0] * (len(b) + 1)
    for i in range(1, len(a) + 1):
        cur = [0] * (len(b) + 1)
        ai = a[i - 1]
        for j in range(1, len(b) + 1):
            cur[j] = prev[j - 1] + 1 if ai == b[j - 1] else max(prev[j], cur[j - 1])
        prev = cur
    return prev[len(b)]


def fuzzy_compare(h1: str, h2: str) -> int:
    """比较两个模糊哈希，返回 0-100 相似度。"""
    if not h1 or not h2:
        return 0
    p1, p2 = h1.split(":"), h2.split(":")
    if len(p1) != 3 or len(p2) != 3:
        return 0
    try:
        b1, b2 = int(p1[0]), int(p2[0])
    except ValueError:
        return 0
    if b1 != b2 and b1 != b2 * 2 and b2 != b1 * 2:
        return 0
    block = min(b1, b2)
    s1 = p1[1] if b1 == block else p1[2]
    s2 = p2[1] if b2 == block else p2[2]
    score = _lcs_length(s1, s2)
    return min(int(score * 100 / (64 * block)), 100)


def compute_hashes(path: str | Path, key: bytes | None = None) -> dict:
    """计算样本的多种哈希指纹。

    :param path: 明文样本路径
    :param key: 预留（用于先解密再哈希的场景由调用方处理）
    """
    path = Path(path)
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    crc = 0
    data_head = b""
    with path.open("rb") as f:
        for block in iter(lambda: f.read(_CHUNK), b""):
            md5.update(block)
            sha1.update(block)
            sha256.update(block)
            crc = zlib.crc32(block, crc)
            if len(data_head) < 1024 * 1024:
                data_head += block[: 1024 * 1024 - len(data_head)]
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "crc32": format(crc & 0xFFFFFFFF, "08x"),
        "size": path.stat().st_size,
        "ssdeep": fuzzy_hash(data_head),
    }
