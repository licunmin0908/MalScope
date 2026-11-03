"""样本加密存储：AES-256-CTR + HMAC-SHA256（Encrypt-then-MAC）。

设计说明：
- 选用 CTR 模式 + 独立 HMAC 而非 GCM，是为了支持超大样本的分块流式加解密，
  同时保证完整性与机密性（先加密后认证，可抵御填充预言与篡改）。
- 文件格式：MAGIC(4) | VERSION(1) | IV(16) | CIPHERTEXT(n) | HMAC-SHA256(32)
- HMAC 覆盖 MAGIC+VERSION+IV+CIPHERTEXT，密钥与 AES 同源但可独立（此处复用主密钥）。
"""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = b"MSEN"
VERSION = b"\x01"
_IV_LEN = 16
_TAG_LEN = 32
_HEADER_LEN = len(MAGIC) + len(VERSION) + _IV_LEN
_CHUNK = 1024 * 1024  # 1MB


class DecryptionError(Exception):
    """样本解密/完整性校验失败。"""


def _hmac(key: bytes, data: bytes) -> hmac.HMAC:
    h = hmac.new(key, digestmod=hashlib.sha256)
    h.update(data)
    return h


def encrypt_bytes(data: bytes, key: bytes) -> bytes:
    """加密字节串，返回带头部与 HMAC 的密文。"""
    iv = os.urandom(_IV_LEN)
    enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    ct = enc.update(data) + enc.finalize()
    mac = _hmac(key, MAGIC + VERSION + iv + ct).digest()
    return MAGIC + VERSION + iv + ct + mac


def decrypt_bytes(blob: bytes, key: bytes) -> bytes:
    """解密并校验字节串。"""
    if len(blob) < _HEADER_LEN + _TAG_LEN or blob[:4] != MAGIC:
        raise DecryptionError("密文格式非法或头部缺失")
    iv = blob[len(MAGIC) + len(VERSION):_HEADER_LEN]
    ct = blob[_HEADER_LEN:-_TAG_LEN]
    mac = blob[-_TAG_LEN:]
    expected = _hmac(key, MAGIC + VERSION + iv + ct).digest()
    if not hmac.compare_digest(mac, expected):
        raise DecryptionError("HMAC 校验失败，密文可能被篡改")
    dec = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
    return dec.update(ct) + dec.finalize()


def encrypt_file(src: str | Path, dst: str | Path, key: bytes) -> str:
    """流式加密文件，返回 IV 的十六进制字符串（非敏感，可入库）。"""
    src, dst = Path(src), Path(dst)
    iv = os.urandom(_IV_LEN)
    h = _hmac(key, MAGIC + VERSION + iv)
    enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    with src.open("rb") as fin, dst.open("wb") as fout:
        fout.write(MAGIC + VERSION + iv)
        while True:
            chunk = fin.read(_CHUNK)
            if not chunk:
                break
            ct = enc.update(chunk)
            h.update(ct)
            fout.write(ct)
        tail = enc.finalize()
        if tail:
            h.update(tail)
            fout.write(tail)
        fout.write(h.digest())
    return iv.hex()


def decrypt_file(src: str | Path, dst: str | Path, key: bytes) -> None:
    """流式解密并校验文件。"""
    src, dst = Path(src), Path(dst)
    size = src.stat().st_size
    if size < _HEADER_LEN + _TAG_LEN:
        raise DecryptionError("密文文件过小")
    ct_len = size - _HEADER_LEN - _TAG_LEN
    with src.open("rb") as fin:
        header = fin.read(_HEADER_LEN)
        if header[:4] != MAGIC:
            raise DecryptionError("密文魔数不匹配")
        iv = header[len(MAGIC) + len(VERSION):]
        # 第一遍：计算 HMAC
        h = _hmac(key, header)
        remaining = ct_len
        while remaining > 0:
            chunk = fin.read(min(_CHUNK, remaining))
            if not chunk:
                break
            h.update(chunk)
            remaining -= len(chunk)
        stored = fin.read(_TAG_LEN)
        if not hmac.compare_digest(stored, h.digest()):
            raise DecryptionError("HMAC 校验失败，样本可能被篡改")

    # 第二遍：解密
    with src.open("rb") as fin, dst.open("wb") as fout:
        fin.seek(_HEADER_LEN)
        dec = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
        remaining = ct_len
        while remaining > 0:
            chunk = fin.read(min(_CHUNK, remaining))
            if not chunk:
                break
            fout.write(dec.update(chunk))
            remaining -= len(chunk)
        tail = dec.finalize()
        if tail:
            fout.write(tail)


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(_CHUNK), b""):
            h.update(block)
    return h.hexdigest()
