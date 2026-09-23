"""keyfort 加密核心：原始字节进、原始字节出（无损，无结构假设）。

- 新格式 KEYFORT1：payload 就是原文件的全部字节，加密即保险箱，
  任何格式的文件都能保护；注入时的 KEY=VALUE 解析发生在使用瞬间，
  不落在存储里。
- 密码不在这里存储：调用方负责（keyring）。
"""
import base64
import binascii
import hashlib
import os
import pathlib

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KDF_ITER = 200000
MAGIC = "KEYFORT1"
FILENAME = ".keyfort"


class WrongPassword(Exception):
    pass


class NotKeyfortFile(Exception):
    """文件不是 KEYFORT1 加密格式（比如把明文文件当成了加密文件）。"""
    pass


def _derive(pw: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, KDF_ITER)


def encrypt_bytes(raw: bytes, pw: str) -> bytes:
    salt, nonce = os.urandom(16), os.urandom(12)
    key = _derive(pw, salt)
    ct = AESGCM(key).encrypt(nonce, raw, None)
    blob = base64.b64encode(salt + nonce + ct).decode()
    return f"{MAGIC}\n{blob}\n".encode("utf-8")


def decrypt_bytes(data: bytes, pw: str) -> bytes:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise NotKeyfortFile("不是 keyfort 加密文件")
    magic, _, b64 = text.strip().partition("\n")
    if magic != MAGIC:
        raise NotKeyfortFile("不是 keyfort 加密文件（KEYFORT1）")
    try:
        blob = base64.b64decode(b64.strip())
    except (binascii.Error, ValueError):
        raise NotKeyfortFile("加密数据损坏（base64 非法，可能被截断或合并冲突）")
    if len(blob) < 28:
        raise NotKeyfortFile("加密数据不完整（可能被截断）")
    salt, nonce, ct = blob[:16], blob[16:28], blob[28:]
    try:
        return AESGCM(_derive(pw, salt)).decrypt(nonce, ct, None)
    except InvalidTag:
        raise WrongPassword("密码不正确")


# ---------------------------------------------------------------- 通用工具
def find(start=None) -> pathlib.Path | None:
    """从 start（默认当前目录）向上找最近的 .keyfort。"""
    d = pathlib.Path(start or os.getcwd()).resolve()
    while True:
        enc = d / FILENAME
        if enc.is_file():
            return enc
        if d.parent == d:
            return None
        d = d.parent


def project_root(enc_path: pathlib.Path) -> pathlib.Path:
    return enc_path.parent


def parse_env_text(text: str) -> dict:
    """标准 dotenv 规则：KEY=VALUE 行；# 注释与空行跳过；值两侧引号剥掉。"""
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        if k:
            out[k] = v
    return out


def dump_env_text(vars: dict) -> str:
    return "".join(f'{k}={v}\n' for k, v in vars.items())


def ensure_gitignore(directory: pathlib.Path, name: str) -> None:
    gi = directory / ".gitignore"
    existing = gi.read_text(encoding="utf-8") if gi.exists() else ""
    if name not in existing.split():
        sep = "" if not existing or existing.endswith("\n") else "\n"
        gi.write_text(existing + f"{sep}{name}\n", encoding="utf-8")
