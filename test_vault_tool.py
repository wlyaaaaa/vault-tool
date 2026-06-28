"""
vault_tool 单元测试

运行方式：python -m pytest test_vault_tool.py -v
或：      python test_vault_tool.py
"""

import os
import sys
import struct
import secrets
import tarfile
import io
import tempfile
import shutil
import contextlib
import unittest
from unittest import mock
from pathlib import Path

# 确保能导入同目录下的 vault_tool
sys.path.insert(0, str(Path(__file__).parent))

import vault_tool


class TestKeyDerivation(unittest.TestCase):
    """测试密钥派生函数。"""

    def test_scrypt_deterministic(self):
        """相同输入 → 相同密钥。"""
        salt = b"test_salt_32bytes_______________"
        k1 = vault_tool.derive_key_scrypt("password123", salt)
        k2 = vault_tool.derive_key_scrypt("password123", salt)
        self.assertEqual(k1, k2)
        self.assertEqual(len(k1), 32)

    def test_scrypt_different_passwords(self):
        """不同密码 → 不同密钥。"""
        salt = b"test_salt_32bytes_______________"
        k1 = vault_tool.derive_key_scrypt("password_a", salt)
        k2 = vault_tool.derive_key_scrypt("password_b", salt)
        self.assertNotEqual(k1, k2)

    def test_scrypt_different_salts(self):
        """不同 salt → 不同密钥。"""
        k1 = vault_tool.derive_key_scrypt("pw", b"salt_aaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        k2 = vault_tool.derive_key_scrypt("pw", b"salt_bbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        self.assertNotEqual(k1, k2)

    def test_pbkdf2_deterministic(self):
        """PBKDF2 相同输入 → 相同密钥。"""
        salt = b"test_salt_16bytes"
        k1 = vault_tool.derive_key_pbkdf2("password123", salt)
        k2 = vault_tool.derive_key_pbkdf2("password123", salt)
        self.assertEqual(k1, k2)
        self.assertEqual(len(k1), 32)


class TestPackUnpack(unittest.TestCase):
    """测试 VAULT02 加密/解密往返。"""

    def test_roundtrip_small(self):
        """小数据加密后能正确解密。"""
        data = b"Hello, Vault!"
        password = "test_password_!@#"
        blob = vault_tool._pack_vault(password, data)
        result = vault_tool._unpack_vault(password, blob)
        self.assertEqual(bytes(result), data)

    def test_roundtrip_empty(self):
        """空数据往返。"""
        data = b""
        password = "empty_test"
        blob = vault_tool._pack_vault(password, data)
        result = vault_tool._unpack_vault(password, blob)
        self.assertEqual(bytes(result), data)

    def test_roundtrip_large(self):
        """较大数据（1MB）往返。"""
        data = secrets.token_bytes(1024 * 1024)
        password = "large_data_password"
        blob = vault_tool._pack_vault(password, data)
        result = vault_tool._unpack_vault(password, blob)
        self.assertEqual(bytes(result), data)

    def test_wrong_password(self):
        """错误密码应抛 ValueError。"""
        data = b"secret data"
        blob = vault_tool._pack_vault("correct_password", data)
        with self.assertRaises(ValueError):
            vault_tool._unpack_vault("wrong_password", blob)

    def test_returns_bytearray(self):
        """_unpack_vault 应返回 bytearray（方便清零）。"""
        data = b"test"
        blob = vault_tool._pack_vault("pw", data)
        result = vault_tool._unpack_vault("pw", blob)
        self.assertIsInstance(result, bytearray)

    def test_tamper_detection(self):
        """篡改密文应被检测到。"""
        data = b"tamper test data"
        blob = vault_tool._pack_vault("pw", data)
        # 篡改最后一个字节
        tampered = bytearray(blob)
        tampered[-1] ^= 0xFF
        with self.assertRaises(ValueError):
            vault_tool._unpack_vault("pw", bytes(tampered))

    def test_tamper_header(self):
        """篡改头部（AAD）也应被检测到。"""
        data = b"header tamper test"
        blob = vault_tool._pack_vault("pw", data)
        tampered = bytearray(blob)
        # 篡改 header 中 scrypt N 参数的一个字节
        tampered[10] ^= 0x01
        with self.assertRaises(ValueError):
            vault_tool._unpack_vault("pw", bytes(tampered))


class TestVaultFormat(unittest.TestCase):
    """测试容器格式。"""

    def test_magic_v2(self):
        """VAULT02 以正确魔数开头。"""
        blob = vault_tool._pack_vault("pw", b"test")
        self.assertTrue(blob.startswith(b"VAULT02"))

    def test_unknown_format(self):
        """未知格式应抛 ValueError。"""
        with self.assertRaises(ValueError):
            vault_tool._unpack_vault("pw", b"UNKNOWN_FORMAT_DATA")


class TestVaultVersion(unittest.TestCase):
    """测试版本检测。"""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.test_file = self.tmpdir / "test.enc"

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_version_v2(self):
        blob = vault_tool._pack_vault("pw", b"test")
        self.test_file.write_bytes(blob)
        self.assertEqual(vault_tool.vault_version(self.test_file), 2)

    def test_version_v1(self):
        self.test_file.write_bytes(b"VAULT01" + b"\x00" * 100)
        self.assertEqual(vault_tool.vault_version(self.test_file), 1)

    def test_version_unknown(self):
        self.test_file.write_bytes(b"GARBAGE" + b"\x00" * 100)
        self.assertEqual(vault_tool.vault_version(self.test_file), 0)

    def test_version_missing(self):
        missing = self.tmpdir / "nonexistent.enc"
        self.assertIsNone(vault_tool.vault_version(missing))


class TestSecureDelete(unittest.TestCase):
    """测试安全删除。"""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_file_deleted(self):
        f = self.tmpdir / "secret.txt"
        f.write_text("sensitive data")
        self.assertTrue(f.exists())
        vault_tool.secure_delete(f)
        self.assertFalse(f.exists())

    def test_dir_deleted(self):
        d = self.tmpdir / "subdir"
        d.mkdir()
        (d / "file1.txt").write_text("data1")
        (d / "file2.txt").write_text("data2")
        vault_tool.secure_delete_dir(d)
        self.assertFalse(d.exists())

    def test_delete_nonexistent(self):
        """删除不存在的文件不应报错。"""
        vault_tool.secure_delete(self.tmpdir / "no_such_file.txt")

    def test_delete_nonexistent_dir(self):
        """删除不存在的目录不应报错。"""
        vault_tool.secure_delete_dir(self.tmpdir / "no_such_dir")


class TestSafeExtract(unittest.TestCase):
    """测试 tar 路径遍历防护。"""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.dest = self.tmpdir / "output"
        self.dest.mkdir()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_normal_extract(self):
        """正常路径应能成功解压。"""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name="hello.txt")
            data = b"hello world"
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        buf.seek(0)
        with tarfile.open(fileobj=buf, mode="r") as tar:
            vault_tool._safe_extractall(tar, self.dest)
        self.assertTrue((self.dest / "hello.txt").exists())
        self.assertEqual((self.dest / "hello.txt").read_bytes(), b"hello world")

    def test_path_traversal_blocked(self):
        """包含 ../ 的路径应被跳过。"""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name="../../../etc/evil.txt")
            data = b"malicious"
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        buf.seek(0)
        with tarfile.open(fileobj=buf, mode="r") as tar:
            vault_tool._safe_extractall(tar, self.dest)
        # evil.txt 不应出现在 dest 之外
        self.assertFalse((self.tmpdir / "etc").exists())

    def test_absolute_path_blocked(self):
        """绝对路径成员应被跳过。"""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name="/tmp/evil.txt")
            data = b"malicious"
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        buf.seek(0)
        with tarfile.open(fileobj=buf, mode="r") as tar:
            vault_tool._safe_extractall(tar, self.dest)
        self.assertFalse(Path("/tmp/evil.txt").exists() and
                         Path("/tmp/evil.txt").read_bytes() == b"malicious")


class TestClearBytes(unittest.TestCase):
    """测试内存清除。"""

    def test_clear_bytearray(self):
        data = bytearray(b"sensitive data here")
        vault_tool._clear_bytes(data)
        self.assertEqual(data, bytearray(len(b"sensitive data here")))

    def test_clear_none(self):
        """None 不应报错。"""
        vault_tool._clear_bytes(None)

    def test_clear_bytes_noop(self):
        """bytes 对象不可变，_clear_bytes 应为 no-op 不报错。"""
        data = b"immutable"
        vault_tool._clear_bytes(data)  # 不应报错


class TestMakeTar(unittest.TestCase):
    """测试 tar 打包。"""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        # 临时覆盖 SOURCE_DIR
        self._orig_source = vault_tool.SOURCE_DIR
        vault_tool.SOURCE_DIR = self.tmpdir

    def tearDown(self):
        vault_tool.SOURCE_DIR = self._orig_source
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_tar_roundtrip(self):
        """打包的文件能从 tar 中正确取出。"""
        (self.tmpdir / "a.txt").write_text("content_a")
        (self.tmpdir / "b.txt").write_text("content_b")
        files = sorted(self.tmpdir.rglob("*"))
        tar_bytes = vault_tool._make_tar(files)
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r") as tar:
            names = sorted(tar.getnames())
        self.assertIn("a.txt", names)
        self.assertIn("b.txt", names)


class TestVersion(unittest.TestCase):
    """测试版本号。"""

    def test_version_exists(self):
        self.assertTrue(hasattr(vault_tool, "__version__"))

    def test_version_format(self):
        parts = vault_tool.__version__.split(".")
        self.assertEqual(len(parts), 3)
        for p in parts:
            self.assertTrue(p.isdigit())


class TestWarnWeakPassword(unittest.TestCase):
    """测试弱密码警告（不抛异常，只是打印）。"""

    def test_short_password(self):
        """短密码不抛异常。"""
        vault_tool._warn_weak_password("abc")

    def test_long_password(self):
        """长密码不抛异常。"""
        vault_tool._warn_weak_password("a" * 20)


class TestEndToEndEncryptDecrypt(unittest.TestCase):
    """端到端测试：打包 → 加密 → 解密 → 验证内容。"""

    def test_full_cycle(self):
        """创建 tar → pack → unpack → 验证内容完整性。"""
        # 构造一个 tar
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            for name, content in [("note.txt", b"my secret note"),
                                  ("dir/data.json", b'{"key": "value"}')]:
                info = tarfile.TarInfo(name=name)
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
        tar_bytes = buf.getvalue()

        password = "end-to-end-test-password-!@#$%"
        encrypted = vault_tool._pack_vault(password, tar_bytes)
        decrypted = vault_tool._unpack_vault(password, encrypted)

        self.assertEqual(bytes(decrypted), tar_bytes)
        self.assertIsInstance(decrypted, bytearray)

        # 验证 tar 内容
        with tarfile.open(fileobj=io.BytesIO(decrypted), mode="r") as tar:
            self.assertEqual(tar.extractfile("note.txt").read(), b"my secret note")
            self.assertEqual(tar.extractfile("dir/data.json").read(), b'{"key": "value"}')


class TestVault03Roundtrip(unittest.TestCase):
    """VAULT03 单层容器加密/解密往返。"""

    def test_roundtrip(self):
        data = b"vault03 payload \x00\x01\x02" * 50
        blob = vault_tool._pack_vault_v3("pw-strong", data)
        self.assertTrue(blob.startswith(b"VAULT03"))
        pt, layer = vault_tool._unpack_vault_v3("pw-strong", blob)
        self.assertEqual(bytes(pt), data)
        self.assertEqual(layer, 0)
        self.assertIsInstance(pt, bytearray)

    def test_wrong_password(self):
        blob = vault_tool._pack_vault_v3("right", b"secret")
        with self.assertRaises(ValueError):
            vault_tool._unpack_vault_v3("wrong", blob)

    def test_slot0_tamper_detected(self):
        blob = vault_tool._pack_vault_v3("pw", b"data to protect here")
        tampered = bytearray(blob)
        tampered[30] ^= 0xFF  # 落在 slot0 区域
        with self.assertRaises(ValueError):
            vault_tool._unpack_vault_v3("pw", bytes(tampered))

    def test_dispatcher_handles_v2_and_v3(self):
        v2 = vault_tool._pack_vault("pw", b"v2 data")
        pt, layer = vault_tool._decrypt_blob("pw", v2)
        self.assertEqual(bytes(pt), b"v2 data")
        self.assertEqual(layer, 0)
        v3 = vault_tool._pack_vault_v3("pw", b"v3 data")
        pt, layer = vault_tool._decrypt_blob("pw", v3)
        self.assertEqual(bytes(pt), b"v3 data")


class TestKeyfile(unittest.TestCase):
    """密钥文件（双因子）。"""

    def setUp(self):
        self.kf = vault_tool.hashlib.sha256(b"keyfile-bytes").digest()

    def test_flag_set(self):
        blob = vault_tool._pack_vault_v3("pw", b"x", keyfile_hash=self.kf)
        self.assertTrue(blob[7] & vault_tool.FLAG_KEYFILE)

    def test_requires_keyfile(self):
        blob = vault_tool._pack_vault_v3("pw", b"secret", keyfile_hash=self.kf)
        with self.assertRaises(ValueError):
            vault_tool._unpack_vault_v3("pw", blob)  # 缺密钥文件
        with self.assertRaises(ValueError):
            vault_tool._unpack_vault_v3("pw", blob,
                                        vault_tool.hashlib.sha256(b"wrong").digest())
        pt, _ = vault_tool._unpack_vault_v3("pw", blob, self.kf)
        self.assertEqual(bytes(pt), b"secret")

    def test_keyfile_alone_insufficient(self):
        blob = vault_tool._pack_vault_v3("pw", b"s", keyfile_hash=self.kf)
        with self.assertRaises(ValueError):
            vault_tool._unpack_vault_v3("bad-pw", blob, self.kf)


class TestDecoy(unittest.TestCase):
    """诱饵密码 / 似真否认（双层）。"""

    def test_two_layers(self):
        real, decoy = b"REAL secrets", b"DECOY fluff"
        blob = vault_tool._pack_vault_v3(
            "real-pw", real, decoy_password="decoy-pw", decoy_plaintext=decoy)
        r_pt, r_lyr = vault_tool._unpack_vault_v3("real-pw", blob)
        d_pt, d_lyr = vault_tool._unpack_vault_v3("decoy-pw", blob)
        self.assertEqual(bytes(r_pt), real)
        self.assertEqual(r_lyr, 1)          # 真实层是隐藏层
        self.assertEqual(bytes(d_pt), decoy)
        self.assertEqual(d_lyr, 0)          # 诱饵层是主层

    def test_third_password_rejected(self):
        blob = vault_tool._pack_vault_v3(
            "real-pw", b"r", decoy_password="decoy-pw", decoy_plaintext=b"d")
        with self.assertRaises(ValueError):
            vault_tool._unpack_vault_v3("other-pw", blob)

    def test_flags_dont_leak_decoy_presence(self):
        """普通库与诱饵库的标志位字节相同，不泄露隐藏层是否存在。"""
        plain = vault_tool._pack_vault_v3("pw", b"data")
        decoy = vault_tool._pack_vault_v3(
            "pw", b"data", decoy_password="d", decoy_plaintext=b"x")
        self.assertEqual(plain[7], decoy[7])


class TestCompression(unittest.TestCase):
    """tar + gzip 压缩。"""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_gzip_and_roundtrip(self):
        (self.tmpdir / "big.txt").write_text("A" * 40000)
        files = sorted(self.tmpdir.rglob("*"))
        tar_bytes = vault_tool._make_tar(files, self.tmpdir)
        self.assertEqual(tar_bytes[:2], b"\x1f\x8b")        # gzip 魔数
        self.assertLess(len(tar_bytes), 40000)              # 确实压缩了
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r") as tar:
            self.assertEqual(tar.extractfile("big.txt").read(), b"A" * 40000)


class TestSteganography(unittest.TestCase):
    """隐写：append 到图片尾部。"""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_hide_extract_roundtrip(self):
        cover = self.tmpdir / "c.jpg"
        cover.write_bytes(b"\xff\xd8\xff" + secrets.token_bytes(500) + b"\xff\xd9")
        payload = self.tmpdir / "v.enc"
        payload.write_bytes(secrets.token_bytes(1234))
        out = self.tmpdir / "stego.jpg"
        plen, total = vault_tool.hide_in_image(cover, payload, out)
        stego = out.read_bytes()
        self.assertEqual(stego[:3], b"\xff\xd8\xff")         # 封面头完好
        self.assertEqual(stego[-8:], vault_tool.STEG_MAGIC)
        rec = self.tmpdir / "rec.enc"
        got = vault_tool.extract_from_image(out, rec)
        self.assertEqual(got, 1234)
        self.assertEqual(rec.read_bytes(), payload.read_bytes())

    def test_plain_image_has_no_payload(self):
        cover = self.tmpdir / "plain.jpg"
        cover.write_bytes(b"\xff\xd8\xff\xd9")
        with self.assertRaises(ValueError):
            vault_tool.extract_from_image(cover, self.tmpdir / "x")


class TestVaultVersionV3(unittest.TestCase):
    """V3 版本与标志位检测。"""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.f = self.tmpdir / "t.enc"

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_version_v3(self):
        self.f.write_bytes(vault_tool._pack_vault_v3("pw", b"x"))
        self.assertEqual(vault_tool.vault_version(self.f), 3)

    def test_flags_keyfile(self):
        kf = vault_tool.hashlib.sha256(b"k").digest()
        self.f.write_bytes(vault_tool._pack_vault_v3("pw", b"x", keyfile_hash=kf))
        self.assertTrue(vault_tool.vault_flags(self.f) & vault_tool.FLAG_KEYFILE)

    def test_flags_none_for_v2(self):
        self.f.write_bytes(vault_tool._pack_vault("pw", b"x"))
        self.assertIsNone(vault_tool.vault_flags(self.f))


class TestSecureZero(unittest.TestCase):
    """memset 快速清零。"""

    def test_zeroes_bytearray(self):
        ba = bytearray(b"sensitive" * 100)
        vault_tool._secure_zero(ba)
        self.assertEqual(ba, bytearray(len(b"sensitive" * 100)))

    def test_empty_and_none_safe(self):
        vault_tool._secure_zero(bytearray())
        vault_tool._secure_zero(None)  # 不应报错


class TestPasswordEntropy(unittest.TestCase):
    """密码强度评估。"""

    def test_empty_is_zero(self):
        self.assertEqual(vault_tool._password_entropy_bits(""), 0.0)

    def test_longer_is_stronger(self):
        weak = vault_tool._password_entropy_bits("abc123")
        strong = vault_tool._password_entropy_bits("correct-horse-battery-staple-river")
        self.assertGreater(strong, weak)

    def test_strength_bar_runs(self):
        self.assertIn("bits", vault_tool._strength_bar("some-password"))


def _fast_kdf(password, salt, n=None, r=None, p=None, keyfile_hash=None):
    """快速、确定性的 KDF 替身：用于交互流程测试（验证编排/IO，而非 KDF 强度）。

    保持"相同输入→相同密钥"，让 pack/unpack 自洽即可；scrypt 的内存硬度由
    TestKeyDerivation 单独覆盖。
    """
    material = password.encode("utf-8") if isinstance(password, str) else bytes(password)
    if keyfile_hash:
        material += keyfile_hash
    import hashlib as _h
    return _h.pbkdf2_hmac("sha256", material, salt, 1)[:32]


class _FlowBase(unittest.TestCase):
    """交互流程测试基类：临时目录 + 快速 KDF + 脚本化 getpass/input。"""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._orig = {k: getattr(vault_tool, k) for k in (
            "SOURCE_DIR", "DECOY_SOURCE_DIR", "DECRYPTED_DIR",
            "VAULT_FILE", "derive_key_scrypt")}
        vault_tool.SOURCE_DIR = self.tmp / "source"
        vault_tool.DECOY_SOURCE_DIR = self.tmp / "decoy_source"
        vault_tool.DECRYPTED_DIR = self.tmp / "decrypted"
        vault_tool.VAULT_FILE = self.tmp / "vault.enc"
        vault_tool.derive_key_scrypt = _fast_kdf
        self._patches = [
            mock.patch.object(vault_tool, "_clear_terminal", lambda: None),
            mock.patch.object(vault_tool, "_pause_or_panic", lambda prompt, cb: None),
        ]
        for p in self._patches:
            p.start()
        self._had_startfile = hasattr(os, "startfile")
        if self._had_startfile:
            self._orig_startfile = os.startfile
            os.startfile = lambda *a, **k: None

    def tearDown(self):
        for p in self._patches:
            p.stop()
        for k, v in self._orig.items():
            setattr(vault_tool, k, v)
        if self._had_startfile:
            os.startfile = self._orig_startfile
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_with(self, fn, getpass_vals, input_vals):
        with mock.patch.object(vault_tool, "getpass", side_effect=list(getpass_vals)), \
             mock.patch("builtins.input", side_effect=list(input_vals)), \
             contextlib.redirect_stdout(io.StringIO()):
            fn()

    def names_in_vault(self, pw, keyfile_hash=None):
        pt, _ = vault_tool._decrypt_blob(pw, vault_tool.VAULT_FILE.read_bytes(), keyfile_hash)
        with tarfile.open(fileobj=io.BytesIO(bytes(pt)), mode="r") as tar:
            return set(tar.getnames())

    def make_source(self, **files):
        vault_tool.SOURCE_DIR.mkdir(parents=True, exist_ok=True)
        for name, content in files.items():
            (vault_tool.SOURCE_DIR / name).write_text(content, encoding="utf-8")


class TestEncryptDecryptFlow(_FlowBase):
    def test_encrypt_creates_v3_and_deletes_source(self):
        self.make_source(**{"a.txt": "alpha", "b.txt": "beta"})
        self.run_with(lambda: vault_tool.encrypt_mode(overwrite=True),
                      ["pw", "pw"], ["n"])
        self.assertTrue(vault_tool.VAULT_FILE.exists())
        self.assertFalse(vault_tool.SOURCE_DIR.exists())
        self.assertEqual(vault_tool.vault_version(vault_tool.VAULT_FILE), 3)
        self.assertEqual(self.names_in_vault("pw"), {"a.txt", "b.txt"})

    def test_decrypt_extract_then_cleans(self):
        self.make_source(**{"note.txt": "secret"})
        self.run_with(lambda: vault_tool.encrypt_mode(overwrite=True), ["pw", "pw"], ["n"])
        self.run_with(lambda: vault_tool.decrypt_mode(force_extract=True), ["pw"], [])
        # 看完后 decrypted/ 应被安全删除
        self.assertFalse(vault_tool.DECRYPTED_DIR.exists()
                         and any(vault_tool.DECRYPTED_DIR.iterdir()))

    def test_encrypt_with_keyfile(self):
        kf = self.tmp / "key.bin"
        kf.write_bytes(b"keyfile-material-123")
        self.make_source(**{"x.txt": "data"})
        self.run_with(lambda: vault_tool.encrypt_mode(
            overwrite=True, keyfile_path=str(kf)), ["pw", "pw"], [])
        flags = vault_tool.vault_flags(vault_tool.VAULT_FILE)
        self.assertTrue(flags & vault_tool.FLAG_KEYFILE)
        # 没密钥文件解不开；有则可以
        with self.assertRaises(ValueError):
            self.names_in_vault("pw")
        kfh = vault_tool._keyfile_hash(str(kf))
        self.assertIn("x.txt", self.names_in_vault("pw", kfh))


class TestAddFilesFlow(_FlowBase):
    def _make_initial(self, pw="pw-A"):
        self.make_source(**{"old.txt": "OLD"})
        self.run_with(lambda: vault_tool.encrypt_mode(overwrite=True), [pw, pw], ["n"])

    def test_merge_preserves_old_and_adds_new(self):
        self._make_initial("pw-A")
        newf = self.tmp / "new.txt"
        newf.write_text("NEW", encoding="utf-8")
        # 合并 Y(回车) → 旧库密码 → 粘贴新路径 → 回车结束 → encrypt keyfile n → 新密码×2
        self.run_with(lambda: vault_tool.add_files_mode(),
                      ["pw-A", "pw-A", "pw-A"], ["", str(newf), "", "n"])
        names = self.names_in_vault("pw-A")
        self.assertIn("old.txt", names)
        self.assertIn("new.txt", names)

    def test_no_merge_overwrites(self):
        self._make_initial("pw-A")
        solo = self.tmp / "solo.txt"
        solo.write_text("SOLO", encoding="utf-8")
        self.run_with(lambda: vault_tool.add_files_mode(),
                      ["pw-B", "pw-B"], ["n", str(solo), "", "n"])
        self.assertEqual(self.names_in_vault("pw-B"), {"solo.txt"})


class TestChangePasswordFlow(_FlowBase):
    def test_change_password(self):
        self.make_source(**{"x.txt": "data"})
        self.run_with(lambda: vault_tool.encrypt_mode(overwrite=True), ["old", "old"], ["n"])
        self.run_with(lambda: vault_tool.change_password_mode(),
                      ["old", "new", "new"], ["n"])
        self.assertIn("x.txt", self.names_in_vault("new"))
        with self.assertRaises(ValueError):
            self.names_in_vault("old")


class TestMigrateFlow(_FlowBase):
    def test_v2_to_v3(self):
        vault_tool.VAULT_FILE.write_bytes(vault_tool._pack_vault("pw", b"legacy data"))
        self.assertEqual(vault_tool.vault_version(vault_tool.VAULT_FILE), 2)
        self.run_with(lambda: vault_tool.migrate_mode(), ["pw"], ["n"])
        self.assertEqual(vault_tool.vault_version(vault_tool.VAULT_FILE), 3)
        pt, _ = vault_tool._decrypt_blob("pw", vault_tool.VAULT_FILE.read_bytes())
        self.assertEqual(bytes(pt), b"legacy data")


class TestDecoyFlow(_FlowBase):
    def test_setup_decoy_two_layers(self):
        self.make_source(**{"real.txt": "REAL"})
        self.run_with(lambda: vault_tool.encrypt_mode(overwrite=True),
                      ["realpw", "realpw"], ["n"])
        vault_tool.DECOY_SOURCE_DIR.mkdir(parents=True)
        (vault_tool.DECOY_SOURCE_DIR / "fake.txt").write_text("FAKE", encoding="utf-8")
        self.run_with(lambda: vault_tool.setup_decoy_mode(),
                      ["realpw", "decoypw", "decoypw"], [])
        self.assertIn("real.txt", self.names_in_vault("realpw"))
        self.assertIn("fake.txt", self.names_in_vault("decoypw"))
        self.assertFalse(vault_tool.DECOY_SOURCE_DIR.exists())


class TestMenuLoop(unittest.TestCase):
    """持久菜单循环：只有 [0]/EOF 才退出；异常与中断都回菜单。"""

    def test_loops_until_exit(self):
        calls = []

        def fake_menu():
            calls.append(1)
            return "exit" if len(calls) >= 3 else None

        with mock.patch.object(vault_tool, "_menu", side_effect=fake_menu), \
             mock.patch("builtins.input", return_value=""), \
             contextlib.redirect_stdout(io.StringIO()):
            vault_tool._menu_loop()
        self.assertEqual(len(calls), 3)

    def test_survives_action_exception(self):
        with mock.patch.object(vault_tool, "_menu",
                               side_effect=[ValueError("boom"), "exit"]), \
             mock.patch("builtins.input", return_value=""), \
             contextlib.redirect_stdout(io.StringIO()):
            vault_tool._menu_loop()  # 不应抛出

    def test_survives_vault_locked(self):
        with mock.patch.object(vault_tool, "_menu",
                               side_effect=[vault_tool.VaultLocked("locked"), "exit"]), \
             mock.patch("builtins.input", return_value=""), \
             contextlib.redirect_stdout(io.StringIO()):
            vault_tool._menu_loop()

    def test_keyboardinterrupt_returns_to_menu(self):
        with mock.patch.object(vault_tool, "_menu",
                               side_effect=[KeyboardInterrupt(), "exit"]), \
             mock.patch("builtins.input", return_value=""), \
             contextlib.redirect_stdout(io.StringIO()):
            vault_tool._menu_loop()

    def test_eof_breaks_loop(self):
        with mock.patch.object(vault_tool, "_menu", side_effect=EOFError()), \
             contextlib.redirect_stdout(io.StringIO()):
            vault_tool._menu_loop()  # EOF 应跳出，不死循环


class TestBucketingDeniability(unittest.TestCase):
    """尺寸分桶：容器总大小只由可见层决定，与隐藏层无关。"""

    def test_size_independent_of_hidden(self):
        visible = b"primary visible layer " * 20
        v_none = vault_tool._pack_vault_v3("p", visible)
        v_small = vault_tool._pack_vault_v3(
            "real", b"x", decoy_password="p", decoy_plaintext=visible)
        v_big = vault_tool._pack_vault_v3(
            "real", b"Z" * 40000, decoy_password="p", decoy_plaintext=visible)
        self.assertEqual(len(v_none), len(v_small))
        self.assertEqual(len(v_small), len(v_big))
        self.assertEqual(len(v_none), 65536)  # 64KB 桶

    def test_bucket_grows_with_visible(self):
        small = vault_tool._pack_vault_v3("p", b"a" * 10)
        big = vault_tool._pack_vault_v3("p", b"a" * 200000)
        self.assertLess(len(small), len(big))
        self.assertEqual(len(small), 65536)
        self.assertEqual(len(big), 512 * 1024)

    def test_bucket_size_helper(self):
        self.assertEqual(vault_tool._bucket_size(100), 65536)
        self.assertEqual(vault_tool._bucket_size(200000), 512 * 1024)
        self.assertEqual(vault_tool._bucket_size(70 * 1024 * 1024) % (16 * 1024 * 1024), 0)

    def test_decoy_capacity_error(self):
        with self.assertRaises(ValueError) as cm:
            vault_tool._pack_vault_v3(
                "real", b"R" * 200000, decoy_password="d", decoy_plaintext=b"tiny")
        self.assertIn("诱饵容量不足", str(cm.exception))


class TestArgon2(unittest.TestCase):
    """Argon2id KDF（需 argon2-cffi）。"""

    @unittest.skipUnless(vault_tool._HAS_ARGON2, "argon2-cffi 未安装")
    def test_roundtrip_and_decoy(self):
        kdf = (2, 1, 8192, 1)  # t=1, m=8MiB, p=1（测试用轻量参数）
        blob = vault_tool._pack_vault_v3("argonpw", b"secret", kdf=kdf)
        self.assertEqual(blob[8], 2)  # kdf_id
        pt, _ = vault_tool._unpack_vault_v3("argonpw", blob)
        self.assertEqual(bytes(pt), b"secret")
        with self.assertRaises(ValueError):
            vault_tool._unpack_vault_v3("wrong", blob)
        d = vault_tool._pack_vault_v3(
            "rp", b"REAL", decoy_password="dp", decoy_plaintext=b"DECOY", kdf=kdf)
        pr, lr = vault_tool._unpack_vault_v3("rp", d)
        pd, ld = vault_tool._unpack_vault_v3("dp", d)
        self.assertEqual((bytes(pr), lr), (b"REAL", 1))
        self.assertEqual((bytes(pd), ld), (b"DECOY", 0))


class TestKdfValidation(unittest.TestCase):
    """解密前 KDF 参数防篡改校验。"""

    def test_reject_huge_scrypt_mem(self):
        with self.assertRaises(ValueError):
            vault_tool._validate_kdf(1, 1 << 30, 8, 1)

    def test_reject_non_power_of_two_n(self):
        with self.assertRaises(ValueError):
            vault_tool._validate_kdf(1, 100, 8, 1)

    def test_reject_unknown_kdf(self):
        with self.assertRaises(ValueError):
            vault_tool._validate_kdf(9, 1, 1, 1)

    def test_accept_valid_scrypt(self):
        vault_tool._validate_kdf(1, 1 << 17, 8, 1)  # 不应抛


class TestDeriveMaxmem(unittest.TestCase):
    """maxmem 动态化：高 N 不再被固定 256MB 上限卡死。"""

    def test_high_n_succeeds(self):
        # N=2^19, r=8 → 512MB；旧的固定 256MB maxmem 会抛 ValueError
        key = vault_tool.derive_key_scrypt("pw", b"saltsaltsaltsalt", n=1 << 19, r=8, p=1)
        self.assertEqual(len(key), 32)


class TestKdfCalibration(unittest.TestCase):
    """KDF 自动校准返回合法参数。"""

    def setUp(self):
        vault_tool._KDF_PARAMS_CACHE.clear()

    def tearDown(self):
        vault_tool._KDF_PARAMS_CACHE.clear()

    def test_scrypt_calibration(self):
        kid, a, b, c = vault_tool._calibrate_kdf("scrypt")
        self.assertEqual(kid, 1)
        self.assertEqual(a & (a - 1), 0)             # 2 的幂
        self.assertLessEqual(a, vault_tool.SCRYPT_N_CAP)


class TestSelectiveExtract(unittest.TestCase):
    """选择性提取：name_filter 只解出匹配的文件。"""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.dest = self.tmpdir / "out"
        self.dest.mkdir()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _tar(self, *names):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            for n in names:
                info = tarfile.TarInfo(name=n)
                data = n.encode()
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        buf.seek(0)
        return buf

    def test_filter_extracts_only_matching(self):
        buf = self._tar("apple.txt", "banana.txt", "apricot.md")
        with tarfile.open(fileobj=buf, mode="r") as tar:
            vault_tool._safe_extractall(tar, self.dest, name_filter="ap")
        names = {p.name for p in self.dest.rglob("*") if p.is_file()}
        self.assertEqual(names, {"apple.txt", "apricot.md"})

    def test_no_filter_extracts_all(self):
        buf = self._tar("a.txt", "b.txt")
        with tarfile.open(fileobj=buf, mode="r") as tar:
            vault_tool._safe_extractall(tar, self.dest)
        names = {p.name for p in self.dest.rglob("*") if p.is_file()}
        self.assertEqual(names, {"a.txt", "b.txt"})


class TestExtractSizeGuard(unittest.TestCase):
    """压缩炸弹防护：超过上限需确认。"""

    def test_small_passes(self):
        self.assertTrue(vault_tool._confirm_if_huge(1024))

    def test_huge_requires_confirm_no(self):
        with mock.patch("builtins.input", return_value="no"), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(vault_tool._confirm_if_huge(vault_tool.MAX_EXTRACT_SIZE + 1))

    def test_huge_confirm_yes(self):
        with mock.patch("builtins.input", return_value="yes"), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(vault_tool._confirm_if_huge(vault_tool.MAX_EXTRACT_SIZE + 1))


class TestCleanBackups(unittest.TestCase):
    """清理备份：找出并安全删除 .bak/.pwbak。"""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self._orig_base = vault_tool.BASE
        vault_tool.BASE = self.tmpdir

    def tearDown(self):
        vault_tool.BASE = self._orig_base
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_find_and_clean(self):
        (self.tmpdir / "vault.enc.bak").write_bytes(b"x" * 100)
        (self.tmpdir / "vault.enc.pwbak").write_bytes(b"y" * 100)
        (self.tmpdir / "vault.enc").write_bytes(b"keep")  # 不是备份
        self.assertEqual(len(vault_tool._find_backups()), 2)
        with mock.patch("builtins.input", return_value="yes"), \
             contextlib.redirect_stdout(io.StringIO()):
            vault_tool.clean_backups_mode()
        self.assertEqual(vault_tool._find_backups(), [])
        self.assertTrue((self.tmpdir / "vault.enc").exists())  # 主库保留


class TestClipboard(unittest.TestCase):
    """剪贴板复制（冒烟测试：不崩溃、返回布尔）。"""

    def test_copy_returns_bool(self):
        result = vault_tool._copy_to_clipboard("test-secret")
        self.assertIsInstance(result, bool)

    def test_schedule_clear_no_crash(self):
        vault_tool._clear_clipboard_later(0.01)  # 不应抛


class TestMakeTarGzipMtime(unittest.TestCase):
    """tar.gz 头部 mtime 应固定为 0（去元数据），且仍可往返。"""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_gzip_mtime_zero(self):
        (self.tmpdir / "a.txt").write_text("hello")
        files = sorted(self.tmpdir.rglob("*"))
        data = vault_tool._make_tar(files, self.tmpdir)
        # gzip 头：魔数(2) + 方法(1) + 标志(1) + mtime(4, 小端)
        self.assertEqual(data[:2], b"\x1f\x8b")
        mtime = struct.unpack("<I", data[4:8])[0]
        self.assertEqual(mtime, 0)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r") as tar:
            self.assertEqual(tar.extractfile("a.txt").read(), b"hello")


if __name__ == "__main__":
    unittest.main(verbosity=2)
