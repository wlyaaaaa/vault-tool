"""
保险库工具 - E:\\Vault\\vault_tool.py

加密：source/ 下任意文件（含子目录）-> vault.enc，安全删除原文
解密：vault.enc -> decrypted/，文本直接显示，阅后安全删除（不可恢复）

加密方案（VAULT02，零第三方依赖）：
  - 密钥派生：scrypt（内存硬，抗 GPU/ASIC 暴力破解）
  - 对称加密：AES-256-GCM（带认证标签，可检测篡改）
  - 抗量子：AES-256 对 Grover 算法仍有等效 128 位强度，足够安全
仍兼容解密旧版 VAULT01（PBKDF2-SHA256 + AES-256-CBC）。

⚠️ 安全的真正天花板是“密码本身的熵”，不是算法。
   请使用足够长的口令（建议 6+ 随机单词，或 16+ 位随机串）。
"""

import os
import sys
import hashlib
import secrets
import tarfile
import io
import struct
import shutil
import ctypes
from pathlib import Path
from getpass import getpass

BASE = Path(__file__).parent
SOURCE_DIR = BASE / "source"
DECRYPTED_DIR = BASE / "decrypted"
VAULT_FILE = BASE / "vault.enc"

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


# ───────────────────────── 密钥派生 ─────────────────────────

def derive_key_scrypt(password, salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P):
    return hashlib.scrypt(
        password.encode("utf-8"), salt=salt,
        n=n, r=r, p=p, dklen=32, maxmem=SCRYPT_MAXMEM,
    )


def derive_key_pbkdf2(password, salt):  # 仅用于兼容旧版 VAULT01
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600000)


# ───────────────────────── 安全删除 ─────────────────────────

def secure_delete(filepath):
    """覆写一遍随机数据后删除。
    注意：在 SSD 上由于磨损均衡/TRIM，覆写不保证抹掉原始数据，
    真正可靠的做法是“明文尽量不落盘”。机械硬盘上一遍随机即足够。"""
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


# ───────────────────── AES-256-GCM (Windows CNG) ─────────────────────

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


# ─────────────────── 旧版 AES-256-CBC（仅解密兼容） ───────────────────

def _aes_cbc_decrypt(ciphertext, key, iv):
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
    ciphertext, tag = _aes_gcm("encrypt", key, nonce, plaintext, aad=header)
    return header + tag + struct.pack(">Q", len(ciphertext)) + ciphertext


def _unpack_vault(password, blob):
    """解密 VAULT02 或 VAULT01，返回明文 tar 字节。失败抛 ValueError。"""
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
            return _aes_gcm("decrypt", key, nonce, ciphertext, aad=header, tag=tag)
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
            return padded[:-pad_len]
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


def _collect_source_files():
    if not SOURCE_DIR.exists():
        return []
    return [p for p in sorted(SOURCE_DIR.rglob("*")) if p.is_file()]


def _make_tar(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for f in files:
            tar.add(f, arcname=f.relative_to(SOURCE_DIR).as_posix())
    return buf.getvalue()


# ───────────────────────── 加密 ─────────────────────────

def encrypt_mode(overwrite=False):
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

    print("\n⏳ 正在派生密钥（scrypt，需占用约 128MB 内存，请稍候）...")
    plaintext = _make_tar(files)
    blob = _pack_vault(password, plaintext)

    with open(VAULT_FILE, "wb") as fh:
        fh.write(blob)
    print(f"✅ 已加密保存至：{VAULT_FILE}（{len(blob)/1024:.1f} KB）")

    print("🗑️  安全删除 source/ 原始文件 ...")
    secure_delete_dir(SOURCE_DIR)
    print("✅ 原始文件已安全删除")
    print("\n💡 请牢记密码！丢失密码 = 数据永久无法找回。")


# ───────────────────────── 解密 ─────────────────────────

def decrypt_mode():
    print("=" * 52)
    print("  🔓 解密模式")
    print("=" * 52)

    if not VAULT_FILE.exists():
        print(f"\n❌ 未找到加密文件：{VAULT_FILE}"); return

    ver = vault_version(VAULT_FILE)
    print(f"\n当前保险库格式：{'VAULT02 (scrypt + AES-256-GCM)' if ver == 2 else 'VAULT01 (旧版 PBKDF2 + AES-CBC)'}")

    password = getpass("\n请输入解密密码：")
    if not password:
        print("❌ 密码不能为空"); return

    with open(VAULT_FILE, "rb") as fh:
        blob = fh.read()
    try:
        print("⏳ 正在校验密码并解密 ...")
        plaintext = _unpack_vault(password, blob)
    except ValueError as e:
        print(f"❌ {e}"); return

    if DECRYPTED_DIR.exists():
        secure_delete_dir(DECRYPTED_DIR)
    DECRYPTED_DIR.mkdir(exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(plaintext), mode="r") as tar:
        tar.extractall(DECRYPTED_DIR)

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
        os.startfile(DECRYPTED_DIR)  # 打开文件夹方便查看非文本文件
    except Exception:
        pass

    print("─" * 52)
    input("📖 阅读完毕后按 Enter，明文将被安全删除（不可恢复）...")
    print("\n🗑️  安全删除 decrypted/ ...")
    secure_delete_dir(DECRYPTED_DIR)
    print("✅ 已安全删除")


# ───────────────────────── 一键升级 ─────────────────────────

def migrate_mode():
    print("=" * 52)
    print("  ⬆️  升级加密方案（VAULT01 → VAULT02，明文不落盘）")
    print("=" * 52)

    if vault_version(VAULT_FILE) != 1:
        print("\n当前保险库已是最新格式（VAULT02），无需升级。")
        return

    password = getpass("\n请输入现有密码：")
    if not password:
        print("❌ 密码不能为空"); return

    with open(VAULT_FILE, "rb") as fh:
        blob = fh.read()
    try:
        print("⏳ 解密旧库 ...")
        plaintext = _unpack_vault(password, blob)
    except ValueError as e:
        print(f"❌ {e}"); return

    backup = VAULT_FILE.with_suffix(".enc.v1bak")
    shutil.copy2(VAULT_FILE, backup)
    print(f"📦 已备份旧库到：{backup.name}")

    print("⏳ 用 scrypt + AES-256-GCM 重新加密 ...")
    new_blob = _pack_vault(password, plaintext)
    with open(VAULT_FILE, "wb") as fh:
        fh.write(new_blob)

    # 立即自检：确认新库能用同一密码解开
    try:
        if _unpack_vault(password, new_blob) != plaintext:
            raise ValueError("自检不一致")
    except ValueError:
        shutil.copy2(backup, VAULT_FILE)
        print("❌ 升级自检失败，已回滚到旧库。")
        return

    print(f"\n✅ 升级完成！新格式 VAULT02（{len(new_blob)/1024:.1f} KB）")
    print(f"   确认新库可正常解密后，可手动删除备份：{backup.name}")


# ───────────────────────── 辅助 ─────────────────────────

def _warn_weak_password(password):
    if len(password) < 12:
        print("⚠️ 提示：密码偏短（<12 位）。算法再强也救不了弱密码——")
        print("   建议改用更长的口令（如 6+ 随机单词，或 16+ 位随机串）。")


def _menu():
    ver = vault_version(VAULT_FILE)
    has_source = bool(_collect_source_files())
    print()
    print("=" * 52)
    print("  🗄️  Vault 保险库")
    print("=" * 52)
    print(f"  当前格式：{ {2: 'VAULT02 (scrypt + AES-256-GCM)',1: 'VAULT01 (旧版，建议升级)',0: '未知',}[ver] }")

    options = [("1", "解密查看", lambda: decrypt_mode())]
    if has_source:
        options.append(("2", "用 source/ 里的文件重新加密（覆盖现有库）",
                        lambda: encrypt_mode(overwrite=False)))
    if ver == 1:
        options.append(("3", "一键升级到最新加密（明文不落盘）", migrate_mode))
    options.append(("0", "退出", None))

    print()
    for k, label, _ in options:
        print(f"  [{k}] {label}")
    if not has_source:
        print("  （把文件放进 source/ 后重跑，可重新加密/加入更多文件）")
    choice = input("\n请选择: ").strip()
    for k, _, fn in options:
        if k == choice:
            if fn:
                fn()
            return
    print("无效选择。")


if __name__ == "__main__":
    print()
    if VAULT_FILE.exists():
        _menu()
    elif _collect_source_files():
        encrypt_mode()
    else:
        print("❌ 未找到 vault.enc，且 source/ 下没有文件。")
        print(f"   请把要加密的文件放入 {SOURCE_DIR} 后重新运行。")
    print()
