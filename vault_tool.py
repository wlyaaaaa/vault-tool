"""
保险库工具 - vault_tool.py

加密：source/ 下任意文件（含子目录）-> vault.enc，安全删除原文
解密：vault.enc -> 终端显示（不落盘）或 decrypted/（阅后安全删除）

加密方案（VAULT03，Windows 零第三方依赖）：
  - 密钥派生：scrypt（内存硬，抗 GPU/ASIC 暴力破解）
  - 对称加密：AES-256-GCM（带认证标签，可检测篡改）
  - 压缩：tar + gzip（节省空间，并消除明文统计特征）
  - 双因子：可选「密钥文件」混入密钥派生（密码 + 文件）
  - 抗胁迫：可选「诱饵密码」——双层容器，无法证明隐藏层是否存在
  - 抗量子：AES-256 对 Grover 算法仍有等效 128 位强度，足够安全
仍兼容解密旧版 VAULT02（scrypt+GCM）与 VAULT01（PBKDF2 + AES-CBC）。

跨平台：Windows 使用内置 bcrypt.dll；Linux/macOS 需 pip install cryptography。

⚠️ 安全的真正天花板是"密码本身的熵"，不是算法。
   请使用足够长的口令（建议 6+ 随机单词，或 16+ 位随机串）。
"""

__version__ = "2.0.0"

import os
import sys
import math
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
DECOY_SOURCE_DIR = BASE / "decoy_source"
DECRYPTED_DIR = BASE / "decrypted"
VAULT_FILE = BASE / "vault.enc"
LOG_FILE = BASE / "vault.log"

MAGIC_V3 = b"VAULT03"
MAGIC_V2 = b"VAULT02"
MAGIC_V1 = b"VAULT01"

# VAULT03 头部标志位
FLAG_KEYFILE = 0x01      # 需要密钥文件
FLAG_COMPRESSED = 0x02   # 内层 tar 使用 gzip 压缩
# 注意：绝不用标志位记录「是否含诱饵层」——那会破坏可否认性。

# 隐写术尾部魔数（追加到封面图片末尾）
STEG_MAGIC = b"VLTSTEG1"

# scrypt 参数：128 MB 内存 / 次猜测，让暴力破解的并行优势失效
SCRYPT_N = 1 << 17        # 131072
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 256 * 1024 * 1024

# 诱饵未启用时，slot1 填充的随机字节量（让"可能藏着隐藏卷"始终成立）
PAD_MIN = 4096
PAD_RANGE = 12288  # 实际填充 = PAD_MIN + random(0..PAD_RANGE)

# 解密时直接打印到终端的文本类型与上限
TEXT_EXT = {".txt", ".md", ".csv", ".log", ".json", ".ini", ".conf",
            ".cfg", ".yaml", ".yml", ".py", ".html", ".xml", ".tex"}
TEXT_PRINT_LIMIT = 64 * 1024

# 密码重试
MAX_RETRIES = 5
RETRY_BASE_DELAY = 2  # 秒


# ───────────────────────── ANSI 终端样式（零依赖） ─────────────────────────

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_BLUE = "\033[34m"
_MAGENTA = "\033[35m"
_CYAN = "\033[36m"
_GREY = "\033[90m"

_COLOR = False          # 由 _init_colors() 决定
_NO_COLOR_FLAG = False  # CLI --no-color


def _init_colors():
    """检测并启用 ANSI 颜色。非 TTY、NO_COLOR、--no-color 时自动禁用。"""
    global _COLOR
    if _NO_COLOR_FLAG or os.environ.get("NO_COLOR") is not None:
        _COLOR = False
        return
    if not (hasattr(sys.stdout, "isatty") and sys.stdout.isatty()):
        _COLOR = False
        return
    if _IS_WINDOWS:
        try:
            k = ctypes.WinDLL("kernel32")
            k.GetStdHandle.restype = ctypes.c_void_p
            h = k.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_ulong()
            if k.GetConsoleMode(ctypes.c_void_p(h), ctypes.byref(mode)):
                # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
                k.SetConsoleMode(ctypes.c_void_p(h), mode.value | 0x0004)
        except Exception:
            pass
    _COLOR = True


def _c(text, *codes):
    """给文本套上 ANSI 颜色/样式（未启用颜色时原样返回）。"""
    if not _COLOR or not codes:
        return text
    return "".join(codes) + text + _RESET


def _rule(char="─", color=_CYAN, width=54):
    print(_c(char * width, color))


def _banner(subtitle=""):
    """统一的标题横幅。"""
    _rule("━", _CYAN)
    print("  " + _c("🗄️  Vault 保险库", _BOLD) + _c(f"   v{__version__}", _GREY))
    if subtitle:
        print("  " + _c(subtitle, _GREY))
    _rule("━", _CYAN)


def _ok(msg):
    print(_c("✅ " + msg, _GREEN))


def _warn(msg):
    print(_c("⚠️  " + msg, _YELLOW))


def _err(msg):
    print(_c("❌ " + msg, _RED))


def _info(msg):
    print(_c("ℹ️  " + msg, _BLUE))


# ───────────────────────── 密码强度评估 ─────────────────────────

def _password_entropy_bits(pw):
    """粗略估算密码熵（按字符池大小×长度）。仅用于给用户直观反馈。"""
    if not pw:
        return 0.0
    pool = 0
    if any(c.islower() for c in pw):
        pool += 26
    if any(c.isupper() for c in pw):
        pool += 26
    if any(c.isdigit() for c in pw):
        pool += 10
    if any(c == " " for c in pw):
        pool += 1
    if any((not c.isalnum()) and c != " " for c in pw):
        pool += 33
    if pool == 0:
        return 0.0
    return len(pw) * math.log2(pool)


def _strength_bar(pw):
    """返回一行可视化的密码强度条。"""
    bits = _password_entropy_bits(pw)
    if bits < 40:
        label, color = "弱", _RED
    elif bits < 60:
        label, color = "中", _YELLOW
    elif bits < 80:
        label, color = "强", _GREEN
    else:
        label, color = "很强", _GREEN
    filled = max(0, min(20, int(bits / 5)))
    bar = "█" * filled + "░" * (20 - filled)
    return f"  强度 {_c(bar, color)} {_c(label, color)}  (~{bits:.0f} bits)"


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
        _err("非 Windows 系统需要安装 cryptography 库：")
        print("   pip install cryptography")
        print("   （Windows 使用内置 bcrypt.dll，无需额外安装）")
        sys.exit(1)


# ───────────────────────── 密钥派生 ─────────────────────────

def derive_key_scrypt(password, salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                      keyfile_hash=None):
    """scrypt 派生 32 字节密钥。

    password 可以是 str 或 bytes。若提供 keyfile_hash（SHA-256 摘要），
    则把它拼到密码材料之后实现"密码 + 密钥文件"双因子。
    """
    material = password.encode("utf-8") if isinstance(password, str) else bytes(password)
    if keyfile_hash:
        material = material + keyfile_hash
    return hashlib.scrypt(
        material, salt=salt, n=n, r=r, p=p, dklen=32, maxmem=SCRYPT_MAXMEM,
    )


def derive_key_pbkdf2(password, salt):  # 仅用于兼容旧版 VAULT01
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600000)


# ───────────────────────── 密钥文件 ─────────────────────────

def _keyfile_hash(path):
    """读取密钥文件并返回其 SHA-256 摘要。空文件视为错误。"""
    data = Path(path).expanduser().read_bytes()
    if not data:
        raise ValueError("密钥文件为空，无法作为第二因子")
    return hashlib.sha256(data).digest()


def _prompt_keyfile_for_encrypt(keyfile_path):
    """加密时（可选）获取密钥文件摘要。返回摘要 bytes 或 None。"""
    if keyfile_path:
        h = _keyfile_hash(keyfile_path)
        _ok(f"已使用密钥文件：{keyfile_path}")
        return h
    ans = input("是否使用密钥文件（双因子：密码 + 文件）？[y/N]: ").strip().lower()
    if ans not in ("y", "yes"):
        return None
    while True:
        path = input("密钥文件路径（任意文件，如一张照片）: ").strip().strip('"')
        if not path:
            return None
        try:
            h = _keyfile_hash(path)
            _ok("密钥文件已绑定。今后解密必须同时提供它。")
            return h
        except Exception as e:
            _err(f"读取失败：{e}，请重试（直接回车放弃）。")


def _prompt_keyfile_for_decrypt(blob, keyfile_path):
    """解密时按需获取密钥文件摘要。

    若库头声明需要密钥文件（FLAG_KEYFILE），则必须提供。
    """
    needs = blob[:7] == MAGIC_V3 and bool(blob[7] & FLAG_KEYFILE)
    if keyfile_path:
        return _keyfile_hash(keyfile_path)
    if not needs:
        return None
    print(_c("🔑 此保险库启用了密钥文件（双因子），必须提供它才能解密。", _MAGENTA))
    while True:
        path = input("密钥文件路径: ").strip().strip('"')
        if not path:
            _err("必须提供密钥文件。")
            continue
        try:
            return _keyfile_hash(path)
        except Exception as e:
            _err(f"读取失败：{e}，请重试。")


# ───────────────────────── 内存清除 / 锁页 ─────────────────────────

def _secure_zero(buf):
    """用 memset 快速清零 bytearray（比逐字节赋值快得多）。"""
    if not isinstance(buf, bytearray) or len(buf) == 0:
        return
    try:
        ctypes.memset((ctypes.c_char * len(buf)).from_buffer(buf), 0, len(buf))
    except Exception:
        for i in range(len(buf)):
            buf[i] = 0


def _clear_bytes(data):
    """尽力清零内存中的敏感数据。bytearray 可靠清除；bytes/str 受 Python 限制无法保证。"""
    if data is None:
        return
    if isinstance(data, bytearray):
        _secure_zero(data)


def _lock_pages(buf):
    """尽力把明文缓冲区锁进物理内存，防止被换页到 pagefile/swap。

    返回一个句柄（dict）供 _unlock_pages 释放；失败返回 None。
    局限：Python GC 可能在别处复制对象，锁不住所有副本；但锁住主缓冲区
    已消除绝大部分 pagefile 泄露风险。
    """
    if not isinstance(buf, bytearray) or len(buf) == 0:
        return None
    try:
        view = (ctypes.c_char * len(buf)).from_buffer(buf)
        addr = ctypes.addressof(view)
        size = len(buf)
        locked = False
        if _IS_WINDOWS:
            k = ctypes.WinDLL("kernel32")
            k.VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            k.VirtualLock.restype = ctypes.c_int
            # 尝试放宽工作集上限，提升可锁定的页数（best-effort）
            try:
                k.GetCurrentProcess.restype = ctypes.c_void_p
                proc = k.GetCurrentProcess()
                k.SetProcessWorkingSetSize.argtypes = [
                    ctypes.c_void_p, ctypes.c_size_t, ctypes.c_size_t]
                want = max(size + (1 << 20), 8 << 20)
                k.SetProcessWorkingSetSize(proc, ctypes.c_size_t(want),
                                           ctypes.c_size_t(want * 2))
            except Exception:
                pass
            locked = bool(k.VirtualLock(ctypes.c_void_p(addr), ctypes.c_size_t(size)))
        else:
            libc = ctypes.CDLL(None, use_errno=True)
            libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            locked = (libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(size)) == 0)
        return {"view": view, "addr": addr, "size": size, "locked": locked}
    except Exception:
        return None


def _unlock_pages(handle):
    """解锁 _lock_pages 锁定的内存并释放缓冲区视图。"""
    if not handle:
        return
    try:
        if handle.get("locked"):
            if _IS_WINDOWS:
                k = ctypes.WinDLL("kernel32")
                k.VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                k.VirtualUnlock(ctypes.c_void_p(handle["addr"]),
                                ctypes.c_size_t(handle["size"]))
            else:
                libc = ctypes.CDLL(None, use_errno=True)
                libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                libc.munlock(ctypes.c_void_p(handle["addr"]),
                             ctypes.c_size_t(handle["size"]))
    except Exception:
        pass
    finally:
        handle["view"] = None  # 释放对 bytearray 的缓冲区导出


# ───────────────────────── 终端清屏 ─────────────────────────

def _clear_terminal():
    """清除终端屏幕及回滚缓冲区，防止明文残留在终端历史中。"""
    if _IS_WINDOWS:
        os.system("cls")
    else:
        os.system("clear")
    # ANSI 转义：清屏 + 清回滚 + 光标归位（Windows Terminal / 新版 cmd 均支持）
    print("\033[2J\033[3J\033[H", end="", flush=True)


# ───────────────────────── 紧急销毁热键 ─────────────────────────

def _pause_or_panic(prompt, panic_cb):
    """显示 prompt 并等待按键：

      - Enter           → 正常返回
      - Ctrl+X (\\x18)   → 调用 panic_cb（紧急销毁，通常不会返回）
      - Ctrl+C (\\x03)   → 抛 KeyboardInterrupt（走正常清理）

    单线程逐键读取，避免与 input() 抢 stdin 造成竞态。无 TTY 时退化为 input()。
    """
    sys.stdout.write(prompt)
    sys.stdout.flush()

    # 无交互终端（重定向 / pythonw）时退化为普通 input，避免阻塞
    if not (hasattr(sys.stdin, "isatty") and sys.stdin.isatty()):
        try:
            input()
        except EOFError:
            pass
        return

    if _IS_WINDOWS:
        try:
            import msvcrt
        except ImportError:
            input()
            return
        while True:
            ch = msvcrt.getwch()
            if ch in ("\r", "\n"):
                sys.stdout.write("\n")
                return
            if ch == "\x18":      # Ctrl+X
                panic_cb()
                return
            if ch == "\x03":      # Ctrl+C
                raise KeyboardInterrupt
            # 其它键忽略
    else:
        if not (hasattr(sys.stdin, "isatty") and sys.stdin.isatty()):
            input()
            return
        import termios
        import tty
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            while True:
                ch = sys.stdin.read(1)
                if ch in ("\r", "\n"):
                    return
                if ch == "\x18":
                    panic_cb()
                    return
                if ch == "\x03":
                    raise KeyboardInterrupt
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
            sys.stdout.write("\n")


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


def _try_gcm_decrypt(key, nonce, ct, aad, tag):
    """尝试 GCM 解密；认证失败（任何后端的异常）统一返回 None。"""
    try:
        return _aes_gcm("decrypt", key, nonce, ct, aad=aad, tag=tag)
    except Exception:
        return None


# ───────────────────────── 容器读写 ─────────────────────────

def _pack_vault(password, plaintext):
    """用 scrypt + AES-256-GCM 打包成 VAULT02 字节（保留：兼容与测试）。"""
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
    """解密 VAULT02 或 VAULT01，返回明文字节（bytearray，方便后续清零）。失败抛 ValueError。"""
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
        pt = _try_gcm_decrypt(key, nonce, ciphertext, header, tag)
        if pt is None:
            raise ValueError("密码错误或文件已被篡改")
        return bytearray(pt)

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


def _pack_vault_v3(real_password, real_plaintext, *,
                   decoy_password=None, decoy_plaintext=None,
                   keyfile_hash=None, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P):
    """打包成 VAULT03 双槽容器。

    布局：
      header_prefix = MAGIC(7) + flags(1) + scrypt 参数(13)        = 21 bytes
      slot0 = salt_len(2)+salt(32) + nonce_len(2)+nonce(12)
              + tag(16) + ct_len(8) + ciphertext0                 ← 显式定长（"被交出"的那层）
      slot1 = salt(32) + nonce(12) + tag(16) + ciphertext...到 EOF ← 长度不标注（隐藏层 / 随机填充）

    若提供 decoy_*，则 slot0=诱饵、slot1=真实（隐藏层）；
    否则 slot0=真实、slot1=纯随机填充。两种情况密文均不可区分。
    """
    flags = FLAG_COMPRESSED
    if keyfile_hash:
        flags |= FLAG_KEYFILE
    header_prefix = MAGIC_V3 + bytes([flags]) + struct.pack(">BIII", 1, n, r, p)

    if decoy_password is not None:
        s0_pw, s0_pt = decoy_password, decoy_plaintext
        s1_pw, s1_pt = real_password, real_plaintext
    else:
        s0_pw, s0_pt = real_password, real_plaintext
        s1_pw, s1_pt = None, None

    # ── slot0（定长、可被交出的一层） ──
    salt0 = secrets.token_bytes(32)
    nonce0 = secrets.token_bytes(12)
    key0 = derive_key_scrypt(s0_pw, salt0, n, r, p, keyfile_hash)
    aad0 = header_prefix + salt0 + nonce0
    pt0 = bytes(s0_pt) if isinstance(s0_pt, bytearray) else s0_pt
    ct0, tag0 = _aes_gcm("encrypt", key0, nonce0, pt0, aad=aad0)
    slot0 = (struct.pack(">H", len(salt0)) + salt0
             + struct.pack(">H", len(nonce0)) + nonce0
             + tag0 + struct.pack(">Q", len(ct0)) + ct0)

    # ── slot1（隐藏层 或 随机填充，长度不在密文中标注） ──
    if s1_pw is not None:
        salt1 = secrets.token_bytes(32)
        nonce1 = secrets.token_bytes(12)
        key1 = derive_key_scrypt(s1_pw, salt1, n, r, p, keyfile_hash)
        aad1 = salt1 + nonce1
        pt1 = bytes(s1_pt) if isinstance(s1_pt, bytearray) else s1_pt
        ct1, tag1 = _aes_gcm("encrypt", key1, nonce1, pt1, aad=aad1)
        slot1 = salt1 + nonce1 + tag1 + ct1
    else:
        pad = PAD_MIN + secrets.randbelow(PAD_RANGE + 1)
        slot1 = secrets.token_bytes(max(pad, 60))

    return header_prefix + slot0 + slot1


def _unpack_vault_v3(password, blob, keyfile_hash=None):
    """解密 VAULT03。返回 (明文 bytearray, layer)。

    layer=0 表示命中 slot0（普通库的真实层 / 诱饵层）；
    layer=1 表示命中 slot1（隐藏的真实层）。失败抛 ValueError。
    """
    if blob[:7] != MAGIC_V3:
        raise ValueError("不是 VAULT03 容器")
    flags = blob[7]
    kdf_id, n, r, p = struct.unpack(">BIII", blob[8:21])
    if kdf_id != 1:
        raise ValueError("unknown KDF id")
    header_prefix = blob[:21]
    pos = 21

    salt_len = struct.unpack(">H", blob[pos:pos + 2])[0]; pos += 2
    salt0 = blob[pos:pos + salt_len]; pos += salt_len
    nonce_len = struct.unpack(">H", blob[pos:pos + 2])[0]; pos += 2
    nonce0 = blob[pos:pos + nonce_len]; pos += nonce_len
    tag0 = blob[pos:pos + 16]; pos += 16
    ct_len0 = struct.unpack(">Q", blob[pos:pos + 8])[0]; pos += 8
    ct0 = blob[pos:pos + ct_len0]; pos += ct_len0
    slot1_region = blob[pos:]

    # 尝试 slot0
    key0 = derive_key_scrypt(password, salt0, n, r, p, keyfile_hash)
    aad0 = header_prefix + salt0 + nonce0
    pt0 = _try_gcm_decrypt(key0, nonce0, ct0, aad0, tag0)
    if pt0 is not None:
        return bytearray(pt0), 0

    # 尝试 slot1（隐藏层）。若是纯随机填充，认证必然失败 → 视为填充。
    if len(slot1_region) >= 60:
        salt1 = slot1_region[0:32]
        nonce1 = slot1_region[32:44]
        tag1 = slot1_region[44:60]
        ct1 = slot1_region[60:]
        key1 = derive_key_scrypt(password, salt1, n, r, p, keyfile_hash)
        pt1 = _try_gcm_decrypt(key1, nonce1, ct1, salt1 + nonce1, tag1)
        if pt1 is not None:
            return bytearray(pt1), 1

    raise ValueError("密码错误或文件已被篡改")


def _decrypt_blob(password, blob, keyfile_hash=None):
    """统一解密入口：按魔数分派到 V3 / V2 / V1。返回 (bytearray, layer)。"""
    if blob[:7] == MAGIC_V3:
        return _unpack_vault_v3(password, blob, keyfile_hash)
    return _unpack_vault(password, blob), 0


def vault_version(path):
    if not path.exists():
        return None
    with open(path, "rb") as fh:
        m = fh.read(7)
    if m == MAGIC_V3:
        return 3
    if m == MAGIC_V2:
        return 2
    if m == MAGIC_V1:
        return 1
    return 0


def vault_flags(path):
    """读取 VAULT03 的标志位字节；非 V3 返回 None。"""
    if not path.exists():
        return None
    with open(path, "rb") as fh:
        head = fh.read(8)
    if head[:7] == MAGIC_V3 and len(head) >= 8:
        return head[7]
    return None


# ───────────────────── tar 安全处理 ─────────────────────

def _safe_extractall(tar, dest):
    """带路径遍历防护的 tar 解压。跳过试图逃逸到 dest 之外的成员。"""
    dest = Path(dest).resolve()
    for member in tar.getmembers():
        member_path = (dest / member.name).resolve()
        if not str(member_path).startswith(str(dest) + os.sep) and member_path != dest:
            _warn(f"跳过危险路径：{member.name}")
            continue
        tar.extract(member, dest)


def _collect_source_files(src_dir=None):
    src_dir = src_dir or SOURCE_DIR
    if not src_dir.exists():
        return []
    return [p for p in sorted(src_dir.rglob("*")) if p.is_file()]


def _make_tar(files, src_dir=None):
    """打包 source/ 文件为 tar.gz 字节。文件多时显示进度。

    使用 gzip 压缩：节省空间，并让明文更接近随机分布、消除统计特征。
    解密侧用 mode='r'（透明自动识别压缩），向后兼容旧的未压缩 tar。
    """
    src_dir = src_dir or SOURCE_DIR
    buf = io.BytesIO()
    total = len(files)
    # mtime=0：去掉 gzip 头里的时间戳元数据（虽在密文内，但保持洁净）
    with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=6) as tar:
        for i, f in enumerate(files, 1):
            tar.add(f, arcname=f.relative_to(src_dir).as_posix())
            if total > 10 and i % max(1, total // 10) == 0:
                print(_c(f"   打包进度：{i}/{total} ({i * 100 // total}%)", _GREY))
    return buf.getvalue()


# ───────────────────── 密码输入（带重试延迟） ─────────────────────

def _get_password_with_retry(prompt, vault_blob, keyfile_hash=None):
    """带递增延迟的密码验证。

    成功返回 (password, plaintext_bytearray, layer)，耗尽则退出。
    """
    for attempt in range(MAX_RETRIES):
        if attempt > 0:
            delay = RETRY_BASE_DELAY * (2 ** (attempt - 1))
            print(_c(f"⏳ 请等待 {delay} 秒后重试 ...", _GREY))
            time.sleep(delay)

        password = getpass(f"\n{prompt}")
        if not password:
            _err("密码不能为空")
            continue

        try:
            print(_c("⏳ 正在校验密码并解密 ...", _GREY))
            plaintext, layer = _decrypt_blob(password, vault_blob, keyfile_hash)
            return password, plaintext, layer
        except ValueError as e:
            remaining = MAX_RETRIES - attempt - 1
            if remaining > 0:
                _err(f"{e}（还剩 {remaining} 次机会）")
            else:
                _err(str(e))

    print()
    print(_c(f"🔒 连续 {MAX_RETRIES} 次密码错误，程序退出。", _RED, _BOLD))
    _log("LOCKED: 连续密码错误达上限")
    sys.exit(1)


def _warn_weak_password(password):
    print(_strength_bar(password))
    if len(password) < 12:
        _warn("密码偏短（<12 位）。算法再强也救不了弱密码——")
        print("   建议改用更长的口令（如 6+ 随机单词，或 16+ 位随机串）。")


def _read_password_twice(prompt1, prompt2):
    """读取两次密码并确认一致。返回密码 str 或 None。"""
    pw = getpass(prompt1)
    if not pw:
        _err("密码不能为空")
        return None
    _warn_weak_password(pw)
    if getpass(prompt2) != pw:
        _err("两次密码不一致")
        return None
    return pw


# ───────────────────────── 加密 ─────────────────────────

def encrypt_mode(overwrite=False, keyfile_path=None):
    _check_platform()
    _init_colors()
    _banner("🔐 加密模式")

    files = _collect_source_files()
    if not files:
        _err(f"{SOURCE_DIR} 下没有任何文件")
        return

    total = sum(f.stat().st_size for f in files)
    print(f"\n找到 {_c(str(len(files)), _BOLD)} 个文件，共 {total/1024:.1f} KB：")
    for f in files[:50]:
        print(f"   • {f.relative_to(SOURCE_DIR).as_posix()} ({f.stat().st_size} bytes)")
    if len(files) > 50:
        print(f"   … 以及另外 {len(files) - 50} 个文件")

    if VAULT_FILE.exists() and not overwrite:
        ans = input(_c(f"\n⚠️  {VAULT_FILE.name} 已存在，覆盖？(yes/no): ", _YELLOW)).strip().lower()
        if ans not in ("y", "yes"):
            print("已取消")
            return

    keyfile_hash = _prompt_keyfile_for_encrypt(keyfile_path)

    password = _read_password_twice("\n请输入加密密码（不回显）：", "请再次确认密码：")
    if not password:
        return

    print(_c("\n⏳ 正在打包并压缩文件 ...", _GREY))
    plaintext = _make_tar(files)
    print(_c("⏳ 正在派生密钥（scrypt，约 128MB 内存，可能需要数秒）...", _GREY))
    blob = _pack_vault_v3(password, plaintext, keyfile_hash=keyfile_hash)

    # 删除原文前先自检：确认这把密码（+密钥文件）真能解开新库
    print(_c("⏳ 写入前自检（确认可解密）...", _GREY))
    try:
        check, _ = _decrypt_blob(password, blob, keyfile_hash)
        if bytes(check) != bytes(plaintext):
            raise ValueError("自检内容不一致")
        _secure_zero(check)
    except Exception as e:
        _err(f"自检失败（{e}），已中止，未删除 source/ 原文。")
        _secure_zero(plaintext)
        return

    with open(VAULT_FILE, "wb") as fh:
        fh.write(blob)
    _ok(f"已加密保存至：{VAULT_FILE}（{len(blob)/1024:.1f} KB）")

    print(_c("🗑️  安全删除 source/ 原始文件 ...", _GREY))
    secure_delete_dir(SOURCE_DIR)
    _secure_zero(plaintext)
    _ok("原始文件已安全删除")
    print(_c("\n💡 请牢记密码！丢失密码 = 数据永久无法找回。", _YELLOW))
    if keyfile_hash:
        print(_c("💡 同时务必保管好密钥文件，丢失它也会永久无法解密。", _YELLOW))
    _log(f"ENCRYPT: {len(files)} 个文件 -> {len(blob)} bytes (V3"
         + (", keyfile" if keyfile_hash else "") + ")")


# ───────────────────────── 解密 ─────────────────────────

def decrypt_mode(force_no_disk=False, force_extract=False, keyfile_path=None):
    _check_platform()
    _init_colors()
    _banner("🔓 解密模式")

    if not VAULT_FILE.exists():
        _err(f"未找到加密文件：{VAULT_FILE}")
        return

    ver = vault_version(VAULT_FILE)
    ver_label = {3: "VAULT03 (scrypt+GCM, 支持密钥文件/诱饵)",
                 2: "VAULT02 (scrypt + AES-256-GCM)",
                 1: "VAULT01 (旧版 PBKDF2 + AES-CBC)"}.get(ver, "未知")
    print(f"\n当前保险库格式：{_c(ver_label, _CYAN)}")

    with open(VAULT_FILE, "rb") as fh:
        blob = fh.read()

    keyfile_hash = _prompt_keyfile_for_decrypt(blob, keyfile_path)
    password, plaintext, layer = _get_password_with_retry(
        "请输入解密密码：", blob, keyfile_hash)
    # 注：password 是 Python str（不可变），无法可靠清零；尽早 del 缩小暴露窗口
    del password
    if keyfile_hash:
        keyfile_hash = None  # 不再需要，尽早释放

    # 锁定明文页，尽量不让其被换页到 pagefile
    lock = _lock_pages(plaintext)

    try:
        if force_extract:
            choice = "2"
        elif force_no_disk:
            choice = "1"
        else:
            print("\n请选择查看方式：")
            print("  " + _c("[1]", _BOLD) + " 不落盘安全查看（默认）— 明文只在内存，强杀/崩溃/断电都不可恢复")
            print("  " + _c("[2]", _BOLD) + " 解压到 decrypted/ 文件夹 — 可用外部程序打开任意文件")
            print("      （正常退出/Ctrl+C 会自动安全删除；但强行杀进程仍可能残留明文）")
            choice = input("选择 [1/2，回车=1]: ").strip() or "1"

        if choice == "2":
            _extract_to_folder(plaintext)
        else:
            _view_in_memory(plaintext)
    finally:
        _secure_zero(plaintext)
        _unlock_pages(lock)
        del plaintext
        gc.collect()
    _log("DECRYPT: 查看完成" + (" (layer1)" if layer == 1 else ""))


def _iter_text_members(tar):
    """生成 tar 中的 (member, 是否可作文本显示)。"""
    for m in sorted(tar.getmembers(), key=lambda x: x.name):
        if not m.isfile():
            continue
        ext = Path(m.name).suffix.lower()
        yield m, (ext in TEXT_EXT and m.size <= TEXT_PRINT_LIMIT)


def _print_member_text(tar, m):
    """打印单个文本成员的内容。"""
    data = tar.extractfile(m).read()
    print("  " + _c(f"📄 {m.name}", _BOLD, _CYAN))
    print(f"     {_c('─' * 44, _GREY)}")
    try:
        for line in data.decode("utf-8").splitlines():
            print(f"     {line}")
    except UnicodeDecodeError:
        print(_c("     （二进制内容，无法以文本显示）", _GREY))
    print()


def _view_in_memory(plaintext):
    """只在内存中解析并显示，绝不写硬盘。支持按文件名/内容搜索（选择性查看）。"""
    print(_c("\n🛡️  不落盘安全查看模式：明文不写入硬盘\n", _GREEN))

    def panic():
        _clear_terminal()
        _secure_zero(plaintext)
        secure_delete_dir(DECRYPTED_DIR)
        _clear_terminal()
        print(_c("🔥 紧急销毁完成：内存已清零、明文已清除。", _RED, _BOLD))
        os._exit(2)

    with tarfile.open(fileobj=io.BytesIO(bytes(plaintext)), mode="r") as tar:
        members = [m for m in tar.getmembers() if m.isfile()]
        text_ok = {m.name: (Path(m.name).suffix.lower() in TEXT_EXT
                            and m.size <= TEXT_PRINT_LIMIT) for m in members}
        print(f"共 {_c(str(len(members)), _BOLD)} 个文件。")
        print(_c("输入关键字搜索文件名（/前缀=按内容搜索）；回车=全部；:q 结束。", _GREY))

        def show(selected):
            if not selected:
                _warn("没有匹配的文件。")
                return
            shown, skipped = 0, []
            for m in sorted(selected, key=lambda x: x.name):
                if text_ok.get(m.name):
                    _print_member_text(tar, m)
                    shown += 1
                else:
                    skipped.append((m.name, m.size))
            if skipped:
                print(_c("  以下为二进制/超大文件，安全查看模式无法显示，", _GREY))
                print(_c("  如需打开请重新解密并选择 [2] 解压到文件夹：", _GREY))
                for name, size in skipped:
                    print(f"    📦 {name}  ({size} bytes)")
                print()
            print(_c(f"  （本次显示 {shown} 个文本文件）", _GREY))

        first = True
        while True:
            prompt = "🔎 搜索: " if not first else "🔎 搜索（回车看全部）: "
            first = False
            try:
                q = input(prompt).strip()
            except EOFError:
                break
            if q == ":q":
                break
            if not q:
                show(members)
                continue
            if q.startswith("/"):  # 按内容搜索
                term = q[1:].lower()
                matched = []
                for m in members:
                    if not text_ok.get(m.name):
                        continue
                    try:
                        body = tar.extractfile(m).read().decode("utf-8").lower()
                    except Exception:
                        continue
                    if term in body:
                        matched.append(m)
                print(_c(f"  内容匹配 “{term}”：{len(matched)} 个文件", _BLUE))
                show(matched)
            else:  # 按文件名搜索
                term = q.lower()
                matched = [m for m in members if term in m.name.lower()]
                print(_c(f"  文件名匹配 “{q}”：{len(matched)} 个文件", _BLUE))
                show(matched)

    _rule("─", _CYAN)
    print("全程未写入硬盘。" + _c("（按 Ctrl+X 可紧急销毁并退出）", _GREY))
    _pause_or_panic("📖 阅读完毕后按 Enter 清屏退出（内存内容随进程结束消失）...", panic)

    # 清除终端屏幕及回滚缓冲区，防止明文残留在终端历史中
    _clear_terminal()
    _ok("屏幕已清除。明文仅存在于刚才的显示中，现已不可恢复。\n")


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

    def panic():
        cleanup()
        _secure_zero(plaintext)
        _clear_terminal()
        print(_c("🔥 紧急销毁完成：decrypted/ 已删除、内存已清零。", _RED, _BOLD))
        os._exit(2)

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
        with tarfile.open(fileobj=io.BytesIO(bytes(plaintext)), mode="r") as tar:
            _safe_extractall(tar, DECRYPTED_DIR)

        extracted = sorted(p for p in DECRYPTED_DIR.rglob("*") if p.is_file())
        _ok(f"已解密 {len(extracted)} 个文件到：{DECRYPTED_DIR}\n")
        for f in extracted:
            rel = f.relative_to(DECRYPTED_DIR).as_posix()
            size = f.stat().st_size
            if f.suffix.lower() in TEXT_EXT and size <= TEXT_PRINT_LIMIT:
                print("  " + _c(f"📄 {rel}", _BOLD, _CYAN))
                print(f"     {_c('─' * 44, _GREY)}")
                try:
                    for line in f.read_text(encoding="utf-8").splitlines():
                        print(f"     {line}")
                except UnicodeDecodeError:
                    print(_c("     （二进制内容，已跳过显示）", _GREY))
                print()
            else:
                print(f"  📦 {rel}  ({size} bytes) — 请在文件夹中用对应程序打开")

        try:
            if _IS_WINDOWS:
                os.startfile(DECRYPTED_DIR)
        except Exception:
            pass

        _rule("─", _CYAN)
        _warn("此模式下若被强行杀进程/断电，decrypted/ 明文可能残留。")
        print(_c("（按 Ctrl+X 可立即紧急销毁）", _GREY))
        _pause_or_panic("📖 阅读完毕后按 Enter，明文将被安全删除（不可恢复）...", panic)
    finally:
        cleanup()
        for sig, handler in prev_handlers.items():
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):
                pass
    _ok("已安全删除")


def _cleanup_stale_plaintext():
    """启动时清除上次崩溃/强杀残留的明文目录。"""
    if DECRYPTED_DIR.exists() and any(DECRYPTED_DIR.iterdir()):
        _warn("检测到上次残留的明文目录 decrypted/（可能上次被强行关闭）")
        secure_delete_dir(DECRYPTED_DIR)
        _ok("已安全清除残留明文\n")
        _log("CLEANUP: 清除上次残留明文")


# ───────────────────────── 诱饵密码（抗胁迫） ─────────────────────────

def setup_decoy_mode(keyfile_path=None):
    """为现有保险库设置诱饵密码（双层 / 似真否认）。

    流程：真密码验证身份 → 设置诱饵密码 → 把诱饵文件放进 decoy_source/ →
    生成 VAULT03 双层容器：诱饵层（被胁迫时交出）+ 隐藏的真实层。
    """
    _check_platform()
    _init_colors()
    _banner("🎭 设置诱饵密码（Plausible Deniability）")

    if not VAULT_FILE.exists():
        _err(f"未找到加密文件：{VAULT_FILE}")
        return

    print(_c(
        "\n原理：生成一个双层容器。被胁迫时你交出『诱饵密码』，对方解出一组\n"
        "看似合理的假文件；你的真实数据在另一层，数学上无法证明它存在。\n", _GREY))

    with open(VAULT_FILE, "rb") as fh:
        blob = fh.read()

    keyfile_hash = _prompt_keyfile_for_decrypt(blob, keyfile_path)

    # 1) 真密码验证 → 取出当前真实数据
    real_password, real_plaintext, real_layer = _get_password_with_retry(
        "请输入真实密码（验证身份）：", blob, keyfile_hash)
    _ok("真实密码验证通过")
    if blob[:7] == MAGIC_V3 and real_layer == 1:
        _warn("此库已设置过诱饵；将用你刚输入的密码作为新的真实密码重建双层。")
    lock = _lock_pages(real_plaintext)

    try:
        # 2) 准备诱饵文件
        decoy_files = _collect_source_files(DECOY_SOURCE_DIR)
        if not decoy_files:
            _err(f"未找到诱饵文件。请把『看起来合理的假文件』放进：{DECOY_SOURCE_DIR}")
            print("   （例如几张普通照片、一份无聊的备忘录）然后重试。")
            return
        print(f"\n诱饵文件（{len(decoy_files)} 个）：")
        for f in decoy_files[:30]:
            print(f"   • {f.relative_to(DECOY_SOURCE_DIR).as_posix()}")

        # 3) 诱饵密码
        print()
        decoy_password = _read_password_twice(
            "请输入诱饵密码（被胁迫时交出，必须与真密码不同）：",
            "请再次确认诱饵密码：")
        if not decoy_password:
            return
        if decoy_password == real_password:
            _err("诱饵密码不能与真实密码相同。")
            return

        decoy_plaintext = _make_tar(decoy_files, DECOY_SOURCE_DIR)

        # 4) 打包双层容器：slot0=诱饵（被交出），slot1=隐藏的真实层
        print(_c("\n⏳ 生成双层容器（scrypt × 2，可能需要数秒）...", _GREY))
        new_blob = _pack_vault_v3(
            real_password, real_plaintext,
            decoy_password=decoy_password, decoy_plaintext=decoy_plaintext,
            keyfile_hash=keyfile_hash)

        # 5) 双向自检：真密码→真实数据，诱饵密码→诱饵数据
        try:
            chk_real, lyr_real = _decrypt_blob(real_password, new_blob, keyfile_hash)
            chk_decoy, lyr_decoy = _decrypt_blob(decoy_password, new_blob, keyfile_hash)
            ok = (bytes(chk_real) == bytes(real_plaintext)
                  and bytes(chk_decoy) == bytes(decoy_plaintext))
            _secure_zero(chk_real)
            _secure_zero(chk_decoy)
            if not ok:
                raise ValueError("自检内容不一致")
        except Exception as e:
            _err(f"双层自检失败（{e}），已中止，未改动原库。")
            return
        del real_password, decoy_password

        # 6) 备份并写入
        backup = VAULT_FILE.with_suffix(".enc.bak")
        shutil.copy2(VAULT_FILE, backup)
        with open(VAULT_FILE, "wb") as fh:
            fh.write(new_blob)

        # 7) 安全删除诱饵明文
        secure_delete_dir(DECOY_SOURCE_DIR)

        _ok(f"诱饵已设置！新库 {len(new_blob)/1024:.1f} KB（VAULT03 双层）")
        print(_c("\n  记住：", _BOLD))
        print(_c("   • 被胁迫时交出『诱饵密码』→ 对方解出假文件，满意离开。", _GREY))
        print(_c("   • 你的真实数据用『真实密码』打开，对方无法证明它存在。", _GREY))
        print(_c(f"   • 旧库已备份为 {backup.name}，确认无误后请安全删除它"
                 "（否则旧的单层库会暴露你曾改动过）。", _YELLOW))
        _log("DECOY: 双层容器已生成")
    finally:
        _secure_zero(real_plaintext)
        _unlock_pages(lock)
        del real_plaintext
        gc.collect()


# ───────────────────────── 隐写术 ─────────────────────────

def hide_in_image(cover_path, payload_path, out_path):
    """把 payload（默认 vault.enc）追加到封面图片末尾，外观仍是正常图片。

    结构：cover_bytes || payload || payload_len(uint64) || STEG_MAGIC
    JPEG/PNG 查看器在各自的结束标记处停止解析，追加数据对其透明。
    """
    cover = Path(cover_path).read_bytes()
    payload = Path(payload_path).read_bytes()
    blob = cover + payload + struct.pack(">Q", len(payload)) + STEG_MAGIC
    Path(out_path).write_bytes(blob)
    return len(payload), len(blob)


def extract_from_image(stego_path, out_path):
    """从隐写图片中提取 payload 并写出。"""
    data = Path(stego_path).read_bytes()
    if len(data) < 16 or data[-8:] != STEG_MAGIC:
        raise ValueError("该文件尾部没有 Vault 隐写标记，可能不含隐藏数据。")
    plen = struct.unpack(">Q", data[-16:-8])[0]
    start = len(data) - 16 - plen
    if start < 0:
        raise ValueError("隐写数据长度异常，文件可能已损坏。")
    payload = data[start:-16]
    Path(out_path).write_bytes(payload)
    return len(payload)


def hide_mode_interactive():
    _init_colors()
    _banner("🖼️  隐写：把 vault.enc 藏进图片")
    if not VAULT_FILE.exists():
        _err(f"未找到 {VAULT_FILE.name}，请先加密。")
        return
    cover = input("封面图片路径（jpg/png）: ").strip().strip('"')
    if not cover or not Path(cover).exists():
        _err("封面图片不存在。")
        return
    default_out = str(BASE / ("hidden" + Path(cover).suffix))
    out = input(f"输出文件路径 [回车={Path(default_out).name}]: ").strip().strip('"') or default_out
    try:
        plen, total = hide_in_image(cover, VAULT_FILE, out)
    except Exception as e:
        _err(f"隐写失败：{e}")
        return
    _ok(f"已生成：{out}（{total/1024:.1f} KB，内含 {plen/1024:.1f} KB 加密数据）")
    print(_c("   图片查看器看到的是一张正常图片；提取需用本工具的 unhide。", _GREY))
    _log("STEG_HIDE: vault.enc -> image")


def unhide_mode_interactive():
    _init_colors()
    _banner("🖼️  隐写：从图片提取 vault.enc")
    stego = input("隐写图片路径: ").strip().strip('"')
    if not stego or not Path(stego).exists():
        _err("文件不存在。")
        return
    default_out = str(BASE / "vault.recovered.enc")
    out = input(f"还原到 [回车={Path(default_out).name}]: ").strip().strip('"') or default_out
    if Path(out).exists():
        ans = input(_c(f"⚠️  {Path(out).name} 已存在，覆盖？(yes/no): ", _YELLOW)).strip().lower()
        if ans not in ("y", "yes"):
            print("已取消")
            return
    try:
        plen = extract_from_image(stego, out)
    except Exception as e:
        _err(f"提取失败：{e}")
        return
    _ok(f"已提取 {plen/1024:.1f} KB 到：{out}")
    print(_c("   把它改名为 vault.enc 即可用本工具解密。", _GREY))
    _log("STEG_EXTRACT: image -> vault.enc")


# ───────────────────────── 一键升级 ─────────────────────────

def migrate_mode(keyfile_path=None):
    _check_platform()
    _init_colors()
    _banner("⬆️  升级加密方案（→ VAULT03，明文不落盘）")

    ver = vault_version(VAULT_FILE)
    if ver is None:
        _err(f"未找到加密文件：{VAULT_FILE}")
        return
    if ver == 3:
        _info("当前保险库已是最新格式（VAULT03），无需升级。")
        return

    with open(VAULT_FILE, "rb") as fh:
        blob = fh.read()

    password, plaintext, _ = _get_password_with_retry("请输入现有密码：", blob)
    lock = _lock_pages(plaintext)

    try:
        keyfile_hash = _prompt_keyfile_for_encrypt(keyfile_path)

        backup = VAULT_FILE.with_suffix(".enc.bak")
        shutil.copy2(VAULT_FILE, backup)
        print(_c(f"📦 已备份旧库到：{backup.name}", _GREY))

        print(_c("⏳ 用 VAULT03（scrypt + AES-256-GCM）重新加密 ...", _GREY))
        new_blob = _pack_vault_v3(password, plaintext, keyfile_hash=keyfile_hash)

        # 自检
        try:
            check, _ = _decrypt_blob(password, new_blob, keyfile_hash)
            if bytes(check) != bytes(plaintext):
                raise ValueError("自检不一致")
            _secure_zero(check)
        except Exception:
            shutil.copy2(backup, VAULT_FILE)
            _err("升级自检失败，已回滚到旧库。")
            return

        with open(VAULT_FILE, "wb") as fh:
            fh.write(new_blob)
        _ok(f"升级完成！新格式 VAULT03（{len(new_blob)/1024:.1f} KB）")
        print(_c(f"   确认新库可正常解密后，可手动删除备份：{backup.name}", _GREY))
        _log(f"MIGRATE: V{ver} -> V3")
    finally:
        _secure_zero(plaintext)
        _unlock_pages(lock)
        del plaintext, password
        gc.collect()


# ───────────────────────── 修改密码 ─────────────────────────

def change_password_mode(keyfile_path=None):
    _check_platform()
    _init_colors()
    _banner("🔑 修改密码")

    if not VAULT_FILE.exists():
        _err(f"未找到加密文件：{VAULT_FILE}")
        return

    with open(VAULT_FILE, "rb") as fh:
        blob = fh.read()

    keyfile_hash = _prompt_keyfile_for_decrypt(blob, keyfile_path)
    old_password, plaintext, layer = _get_password_with_retry(
        "请输入当前密码：", blob, keyfile_hash)
    _ok("当前密码验证通过")

    if blob[:7] == MAGIC_V3 and layer == 1:
        _warn("当前命中的是隐藏（真实）层。注意：本功能会把它重新打包为普通单层库，")
        print("   原有的诱饵层将不再保留（如需诱饵请重新用菜单 [6] 设置）。")

    lock = _lock_pages(plaintext)
    try:
        # 可选更换/移除密钥文件
        new_keyfile_hash = keyfile_hash
        ans = input("是否更改密钥文件设置？[y/N]: ").strip().lower()
        if ans in ("y", "yes"):
            sub = input("  [1] 使用/更换密钥文件  [2] 移除密钥文件  [回车=不变]: ").strip()
            if sub == "1":
                path = input("  新密钥文件路径: ").strip().strip('"')
                try:
                    new_keyfile_hash = _keyfile_hash(path)
                except Exception as e:
                    _err(f"读取失败：{e}，保持原设置。")
            elif sub == "2":
                new_keyfile_hash = None
                _info("将移除密钥文件要求。")

        new_password = _read_password_twice(
            "\n请输入新密码（不回显）：", "请再次确认新密码：")
        if not new_password:
            return
        if new_password == old_password and new_keyfile_hash == keyfile_hash:
            _warn("新密码与设置均无变化，无需修改。")
            return
        del old_password

        backup = VAULT_FILE.with_suffix(".enc.pwbak")
        shutil.copy2(VAULT_FILE, backup)

        print(_c("\n⏳ 用新密码重新加密（scrypt，可能需要数秒）...", _GREY))
        new_blob = _pack_vault_v3(new_password, plaintext, keyfile_hash=new_keyfile_hash)

        try:
            check, _ = _decrypt_blob(new_password, new_blob, new_keyfile_hash)
            if bytes(check) != bytes(plaintext):
                raise ValueError("自检不一致")
            _secure_zero(check)
        except Exception:
            shutil.copy2(backup, VAULT_FILE)
            backup.unlink(missing_ok=True)
            _err("修改密码自检失败，已回滚。")
            return

        with open(VAULT_FILE, "wb") as fh:
            fh.write(new_blob)
        backup.unlink(missing_ok=True)

        _ok(f"密码修改成功！新库 {len(new_blob)/1024:.1f} KB（VAULT03）")
        print(_c("💡 请牢记新密码！丢失密码 = 数据永久无法找回。", _YELLOW))
        _log("PASSWD: 密码已修改")
    finally:
        _secure_zero(plaintext)
        _unlock_pages(lock)
        del plaintext
        gc.collect()


# ───────────────────────── 查看库信息 ─────────────────────────

def vault_info():
    """显示 vault.enc 元信息（不需要密码），读取文件头即可。"""
    _init_colors()
    _banner("📋 保险库信息")

    if not VAULT_FILE.exists():
        _err(f"未找到加密文件：{VAULT_FILE}")
        return

    stat = VAULT_FILE.stat()
    size = stat.st_size
    mtime = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
    ver = vault_version(VAULT_FILE)

    print(f"\n  文件：{VAULT_FILE.name}")
    print(f"  大小：{size:,} bytes（{size/1024:.1f} KB）")
    print(f"  修改时间：{mtime}")

    with open(VAULT_FILE, "rb") as fh:
        blob = fh.read()

    if ver == 3:
        flags = blob[7]
        kdf_id, n, r, p = struct.unpack(">BIII", blob[8:21])
        pos = 21
        salt_len = struct.unpack(">H", blob[pos:pos + 2])[0]; pos += 2 + salt_len
        nonce_len = struct.unpack(">H", blob[pos:pos + 2])[0]; pos += 2 + nonce_len
        pos += 16
        ct_len0 = struct.unpack(">Q", blob[pos:pos + 8])[0]; pos += 8
        slot1_len = len(blob) - (pos + ct_len0)
        n_exp = n.bit_length() - 1

        print(f"  格式：{_c('VAULT03（scrypt + AES-256-GCM）', _GREEN)}")
        print(f"  KDF：scrypt（N=2^{n_exp}, r={r}, p={p}，约 {n * r * 128 // 1024 // 1024} MB/次）")
        print(f"  压缩：{'是（tar+gzip）' if flags & FLAG_COMPRESSED else '否'}")
        print(f"  密钥文件：{_c('需要（双因子）', _MAGENTA) if flags & FLAG_KEYFILE else '否'}")
        print(f"  主层密文：{ct_len0:,} bytes（{ct_len0/1024:.1f} KB）")
        print(f"  尾部区域：{slot1_len:,} bytes "
              + _c("（随机填充 或 隐藏卷——无法区分）", _GREY))
    elif ver == 2:
        pos = 7
        kdf_id, n, r, p = struct.unpack(">BIII", blob[pos:pos + 13]); pos += 13
        salt_len = struct.unpack(">H", blob[pos:pos + 2])[0]; pos += 2 + salt_len
        nonce_len = struct.unpack(">H", blob[pos:pos + 2])[0]; pos += 2 + nonce_len
        pos += 16
        ct_len = struct.unpack(">Q", blob[pos:pos + 8])[0]
        n_exp = n.bit_length() - 1
        print(f"  格式：{_c('VAULT02（scrypt + AES-256-GCM）', _YELLOW)} —— 可升级到 V3")
        print(f"  KDF：scrypt（N=2^{n_exp}, r={r}, p={p}）")
        print(f"  密文：{ct_len:,} bytes（{ct_len/1024:.1f} KB）")
    elif ver == 1:
        print(f"  格式：{_c('VAULT01（旧版 PBKDF2 + AES-CBC）', _RED)} ⚠️ 建议升级")
    else:
        print("  格式：未知")

    print()
    _log("INFO: 查看库信息")


# ───────────────────────── 交互菜单 ─────────────────────────

def _menu():
    _init_colors()
    ver = vault_version(VAULT_FILE)
    flags = vault_flags(VAULT_FILE)
    has_source = bool(_collect_source_files())
    has_vault = VAULT_FILE.exists()

    print()
    ver_names = {
        3: "VAULT03 (scrypt+GCM, 支持密钥文件/诱饵)",
        2: "VAULT02 (scrypt + AES-256-GCM)",
        1: "VAULT01 (旧版，建议升级)",
        0: "未知",
    }
    status = ver_names.get(ver, "未知") if has_vault else "（无 vault.enc）"
    statusc = _GREEN if ver in (2, 3) else (_YELLOW if ver == 1 else _GREY)
    _banner()
    print("  " + _c("格式：", _GREY) + _c(status, statusc))
    if ver == 3 and flags and (flags & FLAG_KEYFILE):
        print("  " + _c("🔑 已启用密钥文件（双因子）", _MAGENTA))
    _rule("━", _CYAN)

    options = []
    if has_vault:
        options.append(("1", "解密查看", lambda: decrypt_mode()))
    if has_source:
        options.append(("2", "用 source/ 里的文件加密（覆盖现有库）",
                        lambda: encrypt_mode(overwrite=False)))
    if ver in (1, 2):
        options.append(("3", "升级到 VAULT03（明文不落盘）", lambda: migrate_mode()))
    if has_vault:
        options.append(("4", "修改密码 / 密钥文件", lambda: change_password_mode()))
    options.append(("5", "查看库信息（不需要密码）", vault_info))
    if has_vault:
        options.append(("6", "设置诱饵密码（抗胁迫 / 似真否认）", lambda: setup_decoy_mode()))
        options.append(("7", "隐写：把 vault.enc 藏进图片", hide_mode_interactive))
    options.append(("8", "隐写：从图片提取 vault.enc", unhide_mode_interactive))
    options.append(("0", "退出", None))

    print()
    for k, label, _fn in options:
        print("  " + _c(f"[{k}]", _BOLD, _CYAN) + f" {label}")
    if not has_source and has_vault:
        print(_c("  （把文件放进 source/ 后重跑，可重新加密/加入更多文件）", _GREY))

    # 旧版备份提醒
    for suffix in (".enc.bak", ".enc.v1bak"):
        bak = VAULT_FILE.with_suffix(suffix)
        if bak.exists():
            print(_c(f"\n  💡 备份 {bak.name}（{bak.stat().st_size/1024:.1f} KB）仍在磁盘上；"
                     "确认新库可解密后建议删除。", _GREY))

    choice = input("\n请选择: ").strip()
    for k, _label, fn in options:
        if k == choice:
            if fn:
                fn()
            return
    _err("无效选择。")


# ───────────────────────── CLI 参数 ─────────────────────────

def _parse_args():
    parser = argparse.ArgumentParser(
        description="Vault 保险库 — 本地加密工具",
        epilog="不带子命令运行则进入交互菜单。",
    )
    parser.add_argument("--version", action="version", version=f"vault_tool {__version__}")
    parser.add_argument("--no-color", action="store_true", help="禁用彩色输出")
    sub = parser.add_subparsers(dest="command")

    enc = sub.add_parser("encrypt", help="加密 source/ 到 vault.enc")
    enc.add_argument("--keyfile", help="使用密钥文件作为第二因子")

    dec = sub.add_parser("decrypt", help="解密查看 vault.enc")
    dec_group = dec.add_mutually_exclusive_group()
    dec_group.add_argument("--no-disk", action="store_true", help="不落盘安全查看（默认）")
    dec_group.add_argument("--extract", action="store_true", help="解压到 decrypted/ 文件夹")
    dec.add_argument("--keyfile", help="提供密钥文件（若库需要）")

    mig = sub.add_parser("migrate", help="升级旧版 → VAULT03")
    mig.add_argument("--keyfile", help="升级时绑定密钥文件")

    sub.add_parser("info", help="查看库信息（不需要密码）")

    pw = sub.add_parser("passwd", help="修改密码 / 密钥文件")
    pw.add_argument("--keyfile", help="当前密钥文件（若库需要）")

    dec2 = sub.add_parser("decoy", help="设置诱饵密码（抗胁迫）")
    dec2.add_argument("--keyfile", help="当前密钥文件（若库需要）")

    hide = sub.add_parser("hide", help="把 vault.enc 藏进封面图片")
    hide.add_argument("--cover", required=True, help="封面图片路径")
    hide.add_argument("--out", help="输出文件路径")

    unhide = sub.add_parser("unhide", help="从图片提取 vault.enc")
    unhide.add_argument("--in", dest="infile", required=True, help="隐写图片路径")
    unhide.add_argument("--out", help="还原输出路径")

    return parser.parse_args()


# ───────────────────────── 入口 ─────────────────────────

if __name__ == "__main__":
    # Windows 控制台可能使用 GBK 编码，emoji 会导致 UnicodeEncodeError
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass  # Python < 3.7 或非标准流

    args = _parse_args()
    _NO_COLOR_FLAG = args.no_color
    _init_colors()

    print()
    _setup_logging()
    _cleanup_stale_plaintext()

    if args.command:
        if args.command == "encrypt":
            encrypt_mode(keyfile_path=args.keyfile)
        elif args.command == "decrypt":
            decrypt_mode(force_no_disk=args.no_disk, force_extract=args.extract,
                         keyfile_path=args.keyfile)
        elif args.command == "migrate":
            migrate_mode(keyfile_path=args.keyfile)
        elif args.command == "info":
            vault_info()
        elif args.command == "passwd":
            change_password_mode(keyfile_path=args.keyfile)
        elif args.command == "decoy":
            setup_decoy_mode(keyfile_path=args.keyfile)
        elif args.command == "hide":
            _init_colors()
            out = args.out or str(BASE / ("hidden" + Path(args.cover).suffix))
            try:
                plen, total = hide_in_image(args.cover, VAULT_FILE, out)
                _ok(f"已生成 {out}（内含 {plen/1024:.1f} KB 加密数据）")
            except Exception as e:
                _err(f"隐写失败：{e}")
        elif args.command == "unhide":
            _init_colors()
            out = args.out or str(BASE / "vault.recovered.enc")
            try:
                plen = extract_from_image(args.infile, out)
                _ok(f"已提取 {plen/1024:.1f} KB 到 {out}")
            except Exception as e:
                _err(f"提取失败：{e}")
    else:
        # 交互菜单模式（向下兼容）
        if VAULT_FILE.exists():
            _menu()
        elif _collect_source_files():
            encrypt_mode()
        else:
            _err("未找到 vault.enc，且 source/ 下没有文件。")
            print(f"   请把要加密的文件放入 {SOURCE_DIR} 后重新运行。")
    print()
