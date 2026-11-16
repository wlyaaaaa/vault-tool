"""Diagnostic output format must not cause file deletion or logging writes."""
import contextlib
import io
import unittest
from unittest import mock
import vault_tool


class ReadOnlyDiagnosticsTests(unittest.TestCase):
    def test_live_snapshot_counts_and_private_stat_only(self):
        import json
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "repo"
            root.mkdir()
            (root / "README.md").write_text("中文 abc 12\n", encoding="utf-8")
            (root / "sample.py").write_text("def test_one():\n    pass\n", encoding="utf-8")
            vault = Path(folder) / "fiction.json"
            vault.write_bytes(b"fiction, never open")
            (vault.parent / "vault.log").write_bytes(b"2026-06-28 01:00:00 | INFO: \xff\n2026-06-28 02:00:00 | ERROR: private\n")
            public, owner = root / "live.json", Path(folder) / "owner.json"
            with mock.patch.object(vault_tool.subprocess, "check_output", return_value=b"README.md\0sample.py\0"), \
                 mock.patch.object(vault_tool, "collect_vault_info", side_effect=AssertionError("no container")):
                vault_tool.write_live_snapshots(public, owner, vault, root)
                first = public.read_bytes()
                vault_tool.write_live_snapshots(public, owner, vault, root)
            self.assertEqual(public.read_bytes(), first)
            data, private = json.loads(first), json.loads(owner.read_bytes())
            self.assertEqual((data["size"]["docs_chars"], data["metrics"]["docs_words"], data["size"]["code_lines"]), (7, 4, 2))
            self.assertEqual((data["metrics"]["test_definitions"], private["metrics"]["legacy_ops"]), (1, 1))
            self.assertEqual(private["metrics"]["local_file"]["bytes"], vault.stat().st_size)
            self.assertNotIn("fiction", first.decode())
            with self.assertRaises(ValueError):
                vault_tool.write_live_snapshots(public, root / "unsafe.json", vault, root)
            with self.assertRaises(ValueError):
                vault_tool.write_live_snapshots(public, vault, vault, root)

    def test_all_diagnostic_formats_skip_mutation_hooks(self):
        for command in ("info", "doctor", "assess", "plan"):
            for json_output in (False, True):
                with self.subTest(command=command, json=json_output):
                    arguments = [command] + (["--json"] if json_output else [])
                    with mock.patch.object(vault_tool, "_setup_logging") as logging, \
                         mock.patch.object(vault_tool, "_cleanup_stale_plaintext") as cleanup, \
                         mock.patch.object(vault_tool, "collect_vault_info", return_value={"ok": False}), \
                         mock.patch.object(vault_tool, "collect_doctor_info", return_value={}), \
                         mock.patch.object(vault_tool, "collect_vault_assessment", return_value={}), \
                         mock.patch.object(vault_tool, "collect_vault_plan", return_value={}), \
                         mock.patch.object(vault_tool, "vault_info", return_value=False), \
                         mock.patch.object(vault_tool, "_print_doctor_info"), \
                         mock.patch.object(vault_tool, "_print_assessment"), \
                         mock.patch.object(vault_tool, "_print_plan"), \
                         contextlib.redirect_stdout(io.StringIO()):
                        vault_tool.main(arguments)
                    logging.assert_not_called()
                    cleanup.assert_not_called()


if __name__ == "__main__":
    unittest.main()
