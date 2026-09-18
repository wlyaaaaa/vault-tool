"""Diagnostic output format must not cause file deletion or logging writes."""
import contextlib
import io
import unittest
from unittest import mock
import vault_tool


class ReadOnlyDiagnosticsTests(unittest.TestCase):
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
