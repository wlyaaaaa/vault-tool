"""
保险库工具 - vault_tool.py

加密：source/ 下任意文件（含子目录）-> vault.enc，安全删除原文
解密：vault.enc -> 终端显示（不落盘）或 decrypted/（阅后安全删除）

加密方案（VAULT02，Windows 零第三方依赖）：
  - 密钥派生：scrypt（内存硬，抗 GPU/ASIC 暴力破解）
  - 对称加密：AES-256-GCM（带认证标签，可检测篡改）
  - 抗量子：AES-256 对 Grover 算法仍有等效 128 位强度，足够安全
仍兼容解密旧版 VAULT01（PBKDF2-SHA256 + AES-256-CBC）。

跨平台：Windows 使用内置 bcrypt.dll；Linux/macOS 需 pip install cryptography。

⚠️ 安全的真正天花板是"密码本身的熵"，不是算法。
   请使用足够长的口令（建议 6+ 随机单词，或 16+ 位随机串）。
"""

__version__ = "1.1.0"

import os
import sys
import hashlib
import secrets
import tarfile
import io
import struct
import shutil
import ctypes
import atexit
import signal
import argparse
import time
import logging
import gc
from pathlib import Path
from getpass import getpass
from datetime import datetime

# ───────────────────────── 平台检测 ─────────────────────────

_IS_WINDOWS = sys.platform == "win32"
_HAS_CRYPTOGRAPHY = False

if not _IS_WINDOWS:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
        from cryptography.hazmat.primitives.ciphers import (
            Cipher as _Cipher, algorithms as _alg, modes as _modes,
        )
        _HAS_CRYPTOGRAPHY = True
    except ImportError:
        pass

# ───────────────────────── 常量 ─────────────────────────

BASE = Path(__file__).parent
SOURCE_DIR = BASE / "source"
DECRYPTED_DIR = BASE / "decrypted"
VAULT_FILE = BASE / "vault.enc"
LOG_FILE = BASE / "vault.log"

MAGIC_V2 = b"VAULT02"
MAGIC_V1 = b"VAULT01"

# scrypt 参数：128 MB 内存 / 次猜测，让暴力破解的并行优势失效
SCRYPT_N = 1 << 17        # 131072
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 256 * 1024 * 1024

# 解密时直接打印到终端的文本类型与上限
TEXT_EXT = {".txt", ".md", ".csv", ".log", ".json", ".ini", ".conf",
            ".cfg", ".yaml", ".yml", ".py", ".html", ".xml", ".tex"}
TEXT_PRINT_LIMIT = 64 * 1024

# 密码重试
MAX_RETRIES = 5
RETRY_BASE_DELAY = 2  # 秒


# ───────────────────────── 日志 ─────────────────────────

def _setup_logging():
    """初始化操作日志（仅记录操作类型和时间，不记录密码或内容）。"""
    try:
        logging.basicConfig(
            filename=str(LOG_FILE),
            level=logging.INFO,
            format="%(asctime)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    except Exception:
        pass


def _log(action):
    """写入一条操作日志，异常不影响主流程。"""
    try:
        logging.info(action)
    except Exception:
        pass


# ───────────────────────── 平台检查 ─────────────────────────

def _check_platform():
    """确保当前平台有可用的加密后端。"""
    if not _IS_WINDOWS and not _HAS_CRYPTOGRAPHY:
        print("❌ 非 Windows 系统需要安装 cryptography 库：")
        print("   pip install cryptography")
        print("   （Windows 使用内置 bcrypt.dll，无需额外安装）")
        sys.exit(1)


# ───────────────────────── 密钥派生 ─────────────────────────

def derive_key_scrypt(password, salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P):
    return hashlib.scrypt(
        password.encode("utf-8"), salt=salt,
        n=n, r=r, p=p, dklen=32, maxmem=SCRYPT_MAXMEM,
    )


def derive_key_pbkdf2(password, salt):  # 仅用于兼容旧版 VAULT01
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600000)


# ───────────────────────── 内存清除 ─────────────────────────

def _clear_bytes(data):
    """尽力清零内存中的敏感数据。bytearray 可靠清除；bytes/str 受 Python 限制无法保证。"""
    if data is None:
        return
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0


# ───────────────────────── 终端清屏 ─────────────────────────

def _clear_terminal():
    """清除终端屏幕及回滚缓冲区，防止明文残留在终端历史中。"""
    if _IS_WINDOWS:
        os.system("cls")
    else:
        os.system("clear")
    # ANSI 转义：清屏 + 清回滚 + 光标归位（Windows Terminal / 新版 cmd 均支持）
    print("\033[2J\033[3J\033[H", end="", flush=True)


# ───────────────────────── 安全删除 ─────────────────────────

def secure_delete(filepath):
    """覆写一遍随机数据后删除。
    注意：在 SSD 上由于磨损均衡/TRIM，覆写不保证抹掉原始数据，
    真正可靠的做法是"明文尽量不落盘"。机械硬盘上一遍随机即足够。"""
    filepath = Path(filepath)
    if not filepath.exists():
        return
    size = filepath.stat().st_size
    try:
        with open(filepath, "r+b", buffering=0) as fh:
            fh.write(secrets.token_bytes(max(size, 512)))
            fh.flush()
            os.fsync(fh.fileno())
    except OSError:
        pass
    filepath.unlink()


def secure_delete_dir(dirpath):
    dirpath = Path(dirpath)
    if not dirpath.exists():
        return
    for f in sorted(dirpath.rglob("*"), key=lambda p: len(str(p)), reverse=True):
        if f.is_file():
            secure_delete(f)
    shutil.rmtree(dirpath, ignore_errors=True)


# ───────────────────── AES-256-GCM / AES-256-CBC ─────────────────────

if _IS_WINDOWS:
    # ── Windows CNG (bcrypt.dll) 实现 ──

    class _AUTHINFO(ctypes.Structure):
        _fields_ = [
            ("cbSize", ctypes.c_ulong), ("dwInfoVersion", ctypes.c_ulong),
            ("pbNonce", ctypes.c_void_p), ("cbNonce", ctypes.c_ulong),
            ("pbAuthData", ctypes.c_void_p), ("cbAuthData", ctypes.c_ulong),
            ("pbTag", ctypes.c_void_p), ("cbTag", ctypes.c_ulong),
            ("pbMacContext", ctypes.c_void_p), ("cbMacContext", ctypes.c_ulong),
            ("cbAAD", ctypes.c_ulong), ("cbData", ctypes.c_ulonglong),
            ("dwFlags", ctypes.c_ulong),
        ]

    def _aes_gcm(mode, key, nonce, data, aad=b"", tag=None):
        bcrypt = ctypes.WinDLL("bcrypt")
        hAlg = ctypes.c_void_p()
        hKey = ctypes.c_void_p()

        if bcrypt.BCryptOpenAlgorithmProvider(ctypes.byref(hAlg), "AES", None, 0) != 0:
            raise OSError("OpenAlgorithmProvider failed")
        try:
            prop = "ChainingMode".encode("utf-16-le") + b"\x00\x00"
            val = "ChainingModeGCM".encode("utf-16-le") + b"\x00\x00"
            if bcrypt.BCryptSetProperty(hAlg, prop, val, len(val), 0) != 0:
                raise OSError("SetProperty GCM failed")

            key_buf = (ctypes.c_ubyte * len(key)).from_buffer_copy(key)
            if bcrypt.BCryptGenerateSymmetricKey(
                hAlg, ctypes.byref(hKey), None, 0, key_buf, len(key), 0
            ) != 0:
                raise OSError("GenerateSymmetricKey failed")
            try:
                nonce_buf = (ctypes.c_ubyte * len(nonce)).from_buffer_copy(nonce)
                tag_buf = (ctypes.c_ubyte * 16)()
                if mode == "decrypt":
                    if tag is None or len(tag) != 16:
                        raise OSError("bad tag")
                    ctypes.memmove(tag_buf, tag, 16)
                aad_buf = (ctypes.c_ubyte * len(aad)).from_buffer_copy(aad) if aad else None

                info = _AUTHINFO()
                info.cbSize = ctypes.sizeof(_AUTHINFO)
                info.dwInfoVersion = 1
                info.pbNonce = ctypes.cast(nonce_buf, ctypes.c_void_p)
                info.cbNonce = len(nonce)
                info.pbTag = ctypes.cast(tag_buf, ctypes.c_void_p)
                info.cbTag = 16
                if aad_buf is not None:
                    info.pbAuthData = ctypes.cast(aad_buf, ctypes.c_void_p)
                    info.cbAuthData = len(aad)

                in_buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data) if data else (ctypes.c_ubyte * 0)()
                out_buf = (ctypes.c_ubyte * len(data))()
                out_len = ctypes.c_ulong(0)
                fn = bcrypt.BCryptEncrypt if mode == "encrypt" else bcrypt.BCryptDecrypt

                st = fn(hKey, in_buf, len(data), ctypes.byref(info), None, 0,
                        out_buf, len(data), ctypes.byref(out_len), 0)
                if st != 0:
                    raise OSError(f"{mode} failed: {st & 0xffffffff:#x}")

                result = bytes(out_buf[:out_len.value])
                if mode == "encrypt":
                    return result, bytes(tag_buf)
                return result
            finally:
                bcrypt.BCryptDestroyKey(hKey)
        finally:
            bcrypt.BCryptCloseAlgorithmProvider(hAlg, 0)

    def _aes_cbc_decrypt(ciphertext, key, iv):
        """旧版 AES-256-CBC 解密（仅用于兼容 VAULT01）。"""
        bcrypt = ctypes.WinDLL("bcrypt")
        hAlg = ctypes.c_void_p()
        hKey = ctypes.c_void_p()
        if bcrypt.BCryptOpenAlgorithmProvider(ctypes.byref(hAlg), "AES", None, 0) != 0:
            raise OSError("OpenAlgorithm failed")
        try:
            prop = "ChainingMode".encode("utf-16-le") + b"\x00\x00"
            val = "ChainingModeCBC".encode("utf-16-le") + b"\x00\x00"
            if bcrypt.BCryptSetProperty(hAlg, prop, val, len(val), 0) != 0:
                raise OSError("SetProperty CBC failed")
            key_buf = (ctypes.c_ubyte * len(key)).from_buffer_copy(key)
            if bcrypt.BCryptGenerateSymmetricKey(
                hAlg, ctypes.byref(hKey), None, 0, key_buf, len(key), 0
            ) != 0:
                raise OSError("GenerateKey failed")
            try:
                iv_buf = (ctypes.c_ubyte * len(iv)).from_buffer_copy(iv)
                iv_prop = "IV".encode("utf-16-le") + b"\x00\x00"
                if bcrypt.BCryptSetProperty(hKey, iv_prop, iv_buf, len(iv), 0) != 0:
                    raise OSError("SetProperty IV failed")
                data_buf = (ctypes.c_ubyte * len(ciphertext)).from_buffer_copy(ciphertext)
                out_len = ctypes.c_ulong(0)
                bcrypt.BCryptDecrypt(hKey, data_buf, len(ciphertext), None, None, 0,
                                     None, 0, ctypes.byref(out_len), 0)
                out_buf = (ctypes.c_ubyte * out_len.value)()
                st = bcrypt.BCryptDecrypt(hKey, data_buf, len(ciphertext), None, None, 0,
                                          out_buf, out_len.value, ctypes.byref(out_len), 0)
                if st != 0:
                    raise OSError("decrypt failed")
                return bytes(out_buf[:out_len.value])
            finally:
                bcrypt.BCryptDestroyKey(hKey)
        finally:
            bcrypt.BCryptCloseAlgorithmProvider(hAlg, 0)

else:
    # ── 跨平台实现（cryptography 库） ──

    def _aes_gcm(mode, key, nonce, data, aad=b"", tag=None):
        _check_platform()
        aesgcm = _AESGCM(key)
        if mode == "encrypt":
            result = aesgcm.encrypt(nonce, data, aad)
            return result[:-16], result[-16:]  # ciphertext, tag
        else:
            return aesgcm.decrypt(nonce, data + tag, aad)

    def _aes_cbc_decrypt(ciphertext, key, iv):
        """旧版 AES-256-CBC 解密（仅用于兼容 VAULT01）。"""
        _check_platform()
        cipher = _Cipher(_alg.AES(key), _modes.CBC(iv))
        d = cipher.decryptor()
        return d.update(ciphertext) + d.finalize()


# ───────────────────────── 容器读写 ─────────────────────────

def _pack_vault(password, plaintext):
    """用 scrypt + AES-256-GCM 打包成 VAULT02 字节。"""
    salt = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    key = derive_key_scrypt(password, salt)
    header = (MAGIC_V2
              + struct.pack(">BIII", 1, SCRYPT_N, SCRYPT_R, SCRYPT_P)
              + struct.pack(">H", len(salt)) + salt
              + struct.pack(">H", len(nonce)) + nonce)
    pt = bytes(plaintext) if isinstance(plaintext, bytearray) else plaintext
    ciphertext, tag = _aes_gcm("encrypt", key, nonce, pt, aad=header)
    return header + tag + struct.pack(">Q", len(ciphertext)) + ciphertext


def _unpack_vault(password, blob):
    """解密 VAULT02 或 VAULT01，返回明文 tar 字节（bytearray，方便后续清零）。
    失败抛 ValueError。"""
    magic = blob[:7]
    if magic == MAGIC_V2:
        pos = 7
        kdf_id, n, r, p = struct.unpack(">BIII", blob[pos:pos + 13]); pos += 13
        salt_len = struct.unpack(">H", blob[pos:pos + 2])[0]; pos += 2
        salt = blob[pos:pos + salt_len]; pos += salt_len
        nonce_len = struct.unpack(">H", blob[pos:pos + 2])[0]; pos += 2
        nonce = blob[pos:pos + nonce_len]; pos += nonce_len
        header = blob[:pos]
        tag = blob[pos:pos + 16]; pos += 16
        ct_len = struct.unpack(">Q", blob[pos:pos + 8])[0]; pos += 8
        ciphertext = blob[pos:pos + ct_len]
        if kdf_id != 1:
            raise ValueError("unknown KDF id")
        key = derive_key_scrypt(password, salt, n=n, r=r, p=p)
        try:
            return bytearray(_aes_gcm("decrypt", key, nonce, ciphertext, aad=header, tag=tag))
        except OSError:
            raise ValueError("密码错误或文件已被篡改")

    if magic == MAGIC_V1:
        pos = 7
        salt_len = struct.unpack(">I", blob[pos:pos + 4])[0]; pos += 4
        salt = blob[pos:pos + salt_len]; pos += salt_len
        iv_len = struct.unpack(">I", blob[pos:pos + 4])[0]; pos += 4
        iv = blob[pos:pos + iv_len]; pos += iv_len
        data_len = struct.unpack(">I", blob[pos:pos + 4])[0]; pos += 4
        ciphertext = blob[pos:pos + data_len]
        key = derive_key_pbkdf2(password, salt)
        try:
            padded = _aes_cbc_decrypt(ciphertext, key[:32], iv)
            pad_len = padded[-1]
            if pad_len < 1 or pad_len > 16:
                raise ValueError
            return bytearray(padded[:-pad_len])
        except Exception:
            raise ValueError("密码错误或文件损坏")

    raise ValueError("文件格式无法识别")


def vault_version(path):
    if not path.exists():
        return None
    with open(path, "rb") as fh:
        m = fh.read(7)
    if m == MAGIC_V2:
        return 2
    if m == MAGIC_V1:
        return 1
    return 0


# ───────────────────── tar 安全处理 ─────────────────────

def _safe_extractall(tar, dest):
    """带路径遍历防护的 tar 解压。跳过试图逃逸到 dest 之外的成员。"""
    dest = Path(dest).resolve()
    for member in tar.getmembers():
        member_path = (dest / member.name).resolve()
        if not str(member_path).startswith(str(dest) + os.sep) and member_path != dest:
            print(f"  ⚠️ 跳过危险路径：{member.name}")
            continue
        tar.extract(member, dest)


def _collect_source_files():
    if not SOURCE_DIR.exists():
        return []
    return [p for p in sorted(SOURCE_DIR.rglob("*")) if p.is_file()]


def _make_tar(files):
    """打包 source/ 文件为 tar 字节。文件多时显示进度。"""
    buf = io.BytesIO()
    total = len(files)
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for i, f in enumerate(files, 1):
            tar.add(f, arcname=f.relative_to(SOURCE_DIR).as_posix())
            if total > 10 and i % max(1, total // 10) == 0:
                print(f"   打包进度：{i}/{total} ({i * 100 // total}%)")
    return buf.getvalue()


# ───────────────────── 密码输入（带重试延迟） ─────────────────────

def _get_password_with_retry(prompt, vault_blob):
    """带递增延迟的密码验证。成功返回 (password, plaintext_bytearray)，耗尽退出。"""
    for attempt in range(MAX_RETRIES):
        if attempt > 0:
            delay = RETRY_BASE_DELAY * (2 ** (attempt - 1))
            print(f"⏳ 请等待 {delay} 秒后重试 ...")
            time.sleep(delay)

        password = getpass(f"\n{prompt}")
        if not password:
            print("❌ 密码不能为空")
            continue

        try:
            print("⏳ 正在校验密码并解密 ...")
            plaintext = _unpack_vault(password, vault_blob)
            return password, plaintext
        except ValueError as e:
            remaining = MAX_RETRIES - attempt - 1
            if remaining > 0:
                print(f"❌ {e}（还剩 {remaining} 次机会）")
            else:
                print(f"❌ {e}")

    print(f"\n🔒 连续 {MAX_RETRIES} 次密码错误，程序退出。")
    _log("LOCKED: 连续密码错误达上限")
    sys.exit(1)


def _warn_weak_password(password):
    if len(password) < 12:
        print("⚠️ 提示：密码偏短（<12 位）。算法再强也救不了弱密码——")
        print("   建议改用更长的口令（如 6+ 随机单词，或 16+ 位随机串）。")


# ───────────────────────── 加密 ─────────────────────────

def encrypt_mode(overwrite=False):
    _check_platform()
    print("=" * 52)
    print("  🔐 加密模式")
    print("=" * 52)

    files = _collect_source_files()
    if not files:
        print(f"\n❌ {SOURCE_DIR} 下没有任何文件")
        return

    total = sum(f.stat().st_size for f in files)
    print(f"\n找到 {len(files)} 个文件，共 {total/1024:.1f} KB：")
    for f in files[:50]:
        print(f"   • {f.relative_to(SOURCE_DIR).as_posix()} ({f.stat().st_size} bytes)")
    if len(files) > 50:
        print(f"   … 以及另外 {len(files) - 50} 个文件")

    if VAULT_FILE.exists() and not overwrite:
        ans = input(f"\n⚠️ {VAULT_FILE.name} 已存在，覆盖？(yes/no): ").strip().lower()
        if ans not in ("y", "yes"):
            print("已取消"); return

    password = getpass("\n请输入加密密码（不回显）：")
    if not password:
        print("❌ 密码不能为空"); return
    _warn_weak_password(password)
    if getpass("请再次确认密码：") != password:
        print("❌ 两次密码不一致"); return

    print("\n⏳ 正在打包文件 ...")
    plaintext = _make_tar(files)
    print(f"⏳ 正在派生密钥（scrypt，约 128MB 内存，可能需要数秒）...")
    blob = _pack_vault(password, plaintext)

    with open(VAULT_FILE, "wb") as fh:
        fh.write(blob)
    print(f"✅ 已加密保存至：{VAULT_FILE}（{len(blob)/1024:.1f} KB）")

    print("🗑️  安全删除 source/ 原始文件 ...")
    secure_delete_dir(SOURCE_DIR)
    print("✅ 原始文件已安全删除")
    print("\n💡 请牢记密码！丢失密码 = 数据永久无法找回。")
    _log(f"ENCRYPT: {len(files)} 个文件 -> {len(blob)} bytes")


# ───────────────────────── 解密 ─────────────────────────

def decrypt_mode(force_no_disk=False, force_extract=False):
    _check_platform()
    print("=" * 52)
    print("  🔓 解密模式")
    print("=" * 52)

    if not VAULT_FILE.exists():
        print(f"\n❌ 未找到加密文件：{VAULT_FILE}"); return

    ver = vault_version(VAULT_FILE)
    print(f"\n当前保险库格式：{'VAULT02 (scrypt + AES-256-GCM)' if ver == 2 else 'VAULT01 (旧版 PBKDF2 + AES-CBC)'}")

    with open(VAULT_FILE, "rb") as fh:
        blob = fh.read()

    password, plaintext = _get_password_with_retry("请输入解密密码：", blob)
    # 注：password 是 Python str（不可变），无法可靠清零；尽早 del 缩小暴露窗口
    del password

    if force_extract:
        choice = "2"
    elif force_no_disk:
        choice = "1"
    else:
        print("\n请选择查看方式：")
        print("  [1] 不落盘安全查看（默认）— 明文只在内存，强杀/崩溃/断电都不可恢复")
        print("  [2] 解压到 decrypted/ 文件夹 — 可用外部程序打开任意文件")
        print("      （正常退出/Ctrl+C 会自动安全删除；但强行杀进程仍可能残留明文）")
        choice = input("选择 [1/2，回车=1]: ").strip() or "1"

    if choice == "2":
        _extract_to_folder(plaintext)
    else:
        _view_in_memory(plaintext)

    _clear_bytes(plaintext)
    del plaintext
    gc.collect()
    _log("DECRYPT: 查看完成")


def _view_in_memory(plaintext):
    """只在内存中解析并显示，绝不写硬盘。进程一旦结束即无法恢复。"""
    print("\n🛡️  不落盘安全查看模式：明文不写入硬盘\n")
    shown = 0
    skipped = []
    with tarfile.open(fileobj=io.BytesIO(plaintext), mode="r") as tar:
        for m in sorted(tar.getmembers(), key=lambda x: x.name):
            if not m.isfile():
                continue
            ext = Path(m.name).suffix.lower()
            if ext in TEXT_EXT and m.size <= TEXT_PRINT_LIMIT:
                data = tar.extractfile(m).read()
                print(f"  📄 {m.name}")
                print(f"     {'─' * 44}")
                try:
                    for line in data.decode("utf-8").splitlines():
                        print(f"     {line}")
                except UnicodeDecodeError:
                    print("     （二进制内容，无法以文本显示）")
                print()
                shown += 1
            else:
                skipped.append((m.name, m.size))

    if skipped:
        print("  以下为二进制/超大文件，安全查看模式无法显示，")
        print("  如需打开请重新解密并选择 [2] 解压到文件夹：")
        for name, size in skipped:
            print(f"    📦 {name}  ({size} bytes)")
        print()

    print("─" * 52)
    print(f"已显示 {shown} 个文本文件，全程未写入硬盘。")
    input("📖 阅读完毕后按 Enter 清屏退出（内存内容随进程结束消失）...")

    # 清除终端屏幕及回滚缓冲区，防止明文残留在终端历史中
    _clear_terminal()
    print("✅ 屏幕已清除。明文仅存在于刚才的显示中，现已不可恢复。\n")


def _extract_to_folder(plaintext):
    """解压到 decrypted/，看完安全删除。
    用 atexit + 信号处理兜底：正常退出、Ctrl+C、SIGTERM、未捕获异常都会清除；
    但 taskkill /F、任务管理器"结束任务"、断电属于强杀，无法运行清理代码。"""
    if DECRYPTED_DIR.exists():
        secure_delete_dir(DECRYPTED_DIR)
    DECRYPTED_DIR.mkdir(exist_ok=True)

    state = {"cleaned": False}

    def cleanup(*_a):
        if not state["cleaned"]:
            state["cleaned"] = True
            secure_delete_dir(DECRYPTED_DIR)

    atexit.register(cleanup)
    prev_handlers = {}
    for signame in ("SIGINT", "SIGTERM", "SIGBREAK"):
        sig = getattr(signal, signame, None)
        if sig is None:
            continue
        try:
            prev_handlers[sig] = signal.signal(sig, lambda *_a: (cleanup(), sys.exit(1)))
        except (ValueError, OSError):
            pass

    try:
        with tarfile.open(fileobj=io.BytesIO(plaintext), mode="r") as tar:
            _safe_extractall(tar, DECRYPTED_DIR)

        extracted = sorted(p for p in DECRYPTED_DIR.rglob("*") if p.is_file())
        print(f"\n✅ 已解密 {len(extracted)} 个文件到：{DECRYPTED_DIR}\n")
        for f in extracted:
            rel = f.relative_to(DECRYPTED_DIR).as_posix()
            size = f.stat().st_size
            if f.suffix.lower() in TEXT_EXT and size <= TEXT_PRINT_LIMIT:
                print(f"  📄 {rel}")
                print(f"     {'─' * 44}")
                try:
                    for line in f.read_text(encoding="utf-8").splitlines():
                        print(f"     {line}")
                except UnicodeDecodeError:
                    print("     （二进制内容，已跳过显示）")
                print()
            else:
                print(f"  📦 {rel}  ({size} bytes) — 请在文件夹中用对应程序打开")

        try:
            if _IS_WINDOWS:
                os.startfile(DECRYPTED_DIR)
        except Exception:
            pass

        print("─" * 52)
        print("⚠️ 注意：此模式下若被强行杀进程/断电，decrypted/ 明文可能残留。")
        input("📖 阅读完毕后按 Enter，明文将被安全删除（不可恢复）...")
    finally:
        cleanup()
        for sig, handler in prev_handlers.items():
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):
                pass
    print("✅ 已安全删除")


def _cleanup_stale_plaintext():
    """启动时清除上次崩溃/强杀残留的明文目录。"""
    if DECRYPTED_DIR.exists() and any(DECRYPTED_DIR.iterdir()):
        print("⚠️ 检测到上次残留的明文目录 decrypted/（可能上次被强行关闭）")
        secure_delete_dir(DECRYPTED_DIR)
        print("✅ 已安全清除残留明文\n")
        _log("CLEANUP: 清除上次残留明文")


# ───────────────────────── 一键升级 ─────────────────────────

def migrate_mode():
    _check_platform()
    print("=" * 52)
    print("  ⬆️  升级加密方案（VAULT01 → VAULT02，明文不落盘）")
    print("=" * 52)

    if vault_version(VAULT_FILE) != 1:
        print("\n当前保险库已是最新格式（VAULT02），无需升级。")
        return

    with open(VAULT_FILE, "rb") as fh:
        blob = fh.read()

    password, plaintext = _get_password_with_retry("请输入现有密码：", blob)

    backup = VAULT_FILE.with_suffix(".enc.v1bak")
    shutil.copy2(VAULT_FILE, backup)
    print(f"📦 已备份旧库到：{backup.name}")

    print("⏳ 用 scrypt + AES-256-GCM 重新加密 ...")
    new_blob = _pack_vault(password, plaintext)
    with open(VAULT_FILE, "wb") as fh:
        fh.write(new_blob)

    # 立即自检：确认新库能用同一密码解开
    try:
        check = _unpack_vault(password, new_blob)
        if bytes(check) != bytes(plaintext):
            raise ValueError("自检不一致")
        _clear_bytes(check)
        del check
    except ValueError:
        shutil.copy2(backup, VAULT_FILE)
        print("❌ 升级自检失败，已回滚到旧库。")
        _clear_bytes(plaintext); del plaintext
        return

    _clear_bytes(plaintext); del plaintext; del password
    gc.collect()

    print(f"\n✅ 升级完成！新格式 VAULT02（{len(new_blob)/1024:.1f} KB）")
    print(f"   确认新库可正常解密后，可手动删除备份：{backup.name}")
    _log("MIGRATE: VAULT01 -> VAULT02")


# ───────────────────────── 修改密码 ─────────────────────────

def change_password_mode():
    _check_platform()
    print("=" * 52)
    print("  🔑 修改密码")
    print("=" * 52)

    if not VAULT_FILE.exists():
        print(f"\n❌ 未找到加密文件：{VAULT_FILE}"); return

    with open(VAULT_FILE, "rb") as fh:
        blob = fh.read()

    old_password, plaintext = _get_password_with_retry("请输入当前密码：", blob)
    print("\n✅ 当前密码验证通过")

    new_password = getpass("\n请输入新密码（不回显）：")
    if not new_password:
        print("❌ 新密码不能为空")
        _clear_bytes(plaintext); del plaintext
        return
    _warn_weak_password(new_password)
    if getpass("请再次确认新密码：") != new_password:
        print("❌ 两次密码不一致")
        _clear_bytes(plaintext); del plaintext
        return
    if new_password == old_password:
        print("⚠️ 新密码与旧密码相同，无需修改。")
        _clear_bytes(plaintext); del plaintext
        return

    del old_password  # 尽早释放旧密码引用

    # 备份
    backup = VAULT_FILE.with_suffix(".enc.pwbak")
    shutil.copy2(VAULT_FILE, backup)

    print("\n⏳ 用新密码重新加密（scrypt，可能需要数秒）...")
    new_blob = _pack_vault(new_password, plaintext)

    # 自检
    try:
        check = _unpack_vault(new_password, new_blob)
        if bytes(check) != bytes(plaintext):
            raise ValueError("自检不一致")
        _clear_bytes(check); del check
    except ValueError:
        shutil.copy2(backup, VAULT_FILE)
        backup.unlink(missing_ok=True)
        print("❌ 修改密码自检失败，已回滚。")
        _clear_bytes(plaintext); del plaintext
        return

    with open(VAULT_FILE, "wb") as fh:
        fh.write(new_blob)
    backup.unlink(missing_ok=True)

    _clear_bytes(plaintext); del plaintext; del new_password
    gc.collect()

    print(f"\n✅ 密码修改成功！新库 {len(new_blob)/1024:.1f} KB")
    print("💡 请牢记新密码！丢失密码 = 数据永久无法找回。")
    _log("PASSWD: 密码已修改")


# ───────────────────────── 查看库信息 ─────────────────────────

def vault_info():
    """显示 vault.enc 元信息（不需要密码），读取文件头即可。"""
    print("=" * 52)
    print("  📋 保险库信息")
    print("=" * 52)

    if not VAULT_FILE.exists():
        print(f"\n❌ 未找到加密文件：{VAULT_FILE}"); return

    stat = VAULT_FILE.stat()
    size = stat.st_size
    mtime = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")

    ver = vault_version(VAULT_FILE)

    print(f"\n  文件：{VAULT_FILE.name}")
    print(f"  大小：{size:,} bytes（{size/1024:.1f} KB）")
    print(f"  修改时间：{mtime}")

    with open(VAULT_FILE, "rb") as fh:
        blob = fh.read()

    if ver == 2:
        pos = 7
        kdf_id, n, r, p = struct.unpack(">BIII", blob[pos:pos + 13]); pos += 13
        salt_len = struct.unpack(">H", blob[pos:pos + 2])[0]; pos += 2
        pos += salt_len
        nonce_len = struct.unpack(">H", blob[pos:pos + 2])[0]; pos += 2
        pos += nonce_len
        pos += 16  # tag
        ct_len = struct.unpack(">Q", blob[pos:pos + 8])[0]

        # 计算 N 的 2 的幂
        n_exp = n.bit_length() - 1

        print(f"  格式：VAULT02（scrypt + AES-256-GCM）")
        print(f"  KDF：scrypt（N=2^{n_exp}, r={r}, p={p}，约 {n * r * 128 // 1024 // 1024} MB/次）")
        print(f"  Salt：{salt_len} bytes")
        print(f"  Nonce：{nonce_len} bytes")
        print(f"  密文：{ct_len:,} bytes（{ct_len/1024:.1f} KB）")
    elif ver == 1:
        pos = 7
        salt_len = struct.unpack(">I", blob[pos:pos + 4])[0]; pos += 4
        pos += salt_len
        iv_len = struct.unpack(">I", blob[pos:pos + 4])[0]; pos += 4
        pos += iv_len
        data_len = struct.unpack(">I", blob[pos:pos + 4])[0]

        print(f"  格式：VAULT01（旧版 PBKDF2 + AES-CBC）⚠️ 建议升级")
        print(f"  Salt：{salt_len} bytes")
        print(f"  IV：{iv_len} bytes")
        print(f"  密文：{data_len:,} bytes（{data_len/1024:.1f} KB）")
    else:
        print("  格式：未知")

    print()
    _log("INFO: 查看库信息")


# ───────────────────────── 交互菜单 ─────────────────────────

def _menu():
    ver = vault_version(VAULT_FILE)
    has_source = bool(_collect_source_files())
    print()
    print("=" * 52)
    print(f"  🗄️  Vault 保险库  v{__version__}")
    print("=" * 52)

    ver_names = {
        2: "VAULT02 (scrypt + AES-256-GCM)",
        1: "VAULT01 (旧版，建议升级)",
        0: "未知",
    }
    print(f"  当前格式：{ver_names.get(ver, '未知')}")

    options = [("1", "解密查看", lambda: decrypt_mode())]
    if has_source:
        options.append(("2", "用 source/ 里的文件重新加密（覆盖现有库）",
                        lambda: encrypt_mode(overwrite=False)))
    if ver == 1:
        options.append(("3", "一键升级到最新加密（明文不落盘）", migrate_mode))
    options.append(("4", "修改密码", change_password_mode))
    options.append(("5", "查看库信息（不需要密码）", vault_info))
    options.append(("0", "退出", None))

    print()
    for k, label, _ in options:
        print(f"  [{k}] {label}")
    if not has_source:
        print("  （把文件放进 source/ 后重跑，可重新加密/加入更多文件）")

    # 旧版备份提醒
    v1bak = VAULT_FILE.with_suffix(".enc.v1bak")
    if v1bak.exists():
        v1bak_size = v1bak.stat().st_size
        print(f"\n  💡 旧版备份 {v1bak.name}（{v1bak_size/1024:.1f} KB）仍在磁盘上。")
        print(f"     确认新库可正常解密后，建议删除它以释放空间。")

    choice = input("\n请选择: ").strip()
    for k, _, fn in options:
        if k == choice:
            if fn:
                fn()
            return
    print("无效选择。")


# ───────────────────────── CLI 参数 ─────────────────────────

def _parse_args():
    parser = argparse.ArgumentParser(
        description="Vault 保险库 — 本地加密工具",
        epilog="不带子命令运行则进入交互菜单。",
    )
    parser.add_argument(
        "--version", action="version",
        version=f"vault_tool {__version__}",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("encrypt", help="加密 source/ 到 vault.enc")

    dec = sub.add_parser("decrypt", help="解密查看 vault.enc")
    dec_group = dec.add_mutually_exclusive_group()
    dec_group.add_argument("--no-disk", action="store_true",
                           help="不落盘安全查看（默认）")
    dec_group.add_argument("--extract", action="store_true",
                           help="解压到 decrypted/ 文件夹")

    sub.add_parser("migrate", help="升级 VAULT01 → VAULT02")
    sub.add_parser("info", help="查看库信息（不需要密码）")
    sub.add_parser("passwd", help="修改密码")

    return parser.parse_args()


# ───────────────────────── 入口 ─────────────────────────

if __name__ == "__main__":
    # Windows 控制台可能使用 GBK 编码，emoji 会导致 UnicodeEncodeError
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass  # Python < 3.7 或非标准流

    print()
    _setup_logging()
    _cleanup_stale_plaintext()

    args = _parse_args()

    if args.command:
        # CLI 模式：直接执行指定子命令
        if args.command == "encrypt":
            encrypt_mode()
        elif args.command == "decrypt":
            decrypt_mode(
                force_no_disk=args.no_disk,
                force_extract=args.extract,
            )
        elif args.command == "migrate":
            migrate_mode()
        elif args.command == "info":
            vault_info()
        elif args.command == "passwd":
            change_password_mode()
    else:
        # 交互菜单模式（向下兼容）
        if VAULT_FILE.exists():
            _menu()
        elif _collect_source_files():
            encrypt_mode()
        else:
            print("❌ 未找到 vault.enc，且 source/ 下没有文件。")
            print(f"   请把要加密的文件放入 {SOURCE_DIR} 后重新运行。")
    print()
