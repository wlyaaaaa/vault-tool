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


if __name__ == "__main__":
    unittest.main(verbosity=2)
