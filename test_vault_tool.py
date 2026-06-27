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
import unittest
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
