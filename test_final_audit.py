"""Final-audit regressions; every filesystem object is a fictional temp fixture."""
from __future__ import annotations
import contextlib
import gzip
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import tarfile
import vault_tool as v

KDF=(1,1024,8,1)
def archive(data):
    buffer=io.BytesIO()
    with tarfile.open(fileobj=buffer,mode='w') as tar:
        item=tarfile.TarInfo('fixture.txt');item.size=len(data);tar.addfile(item,io.BytesIO(data))
    return gzip.compress(buffer.getvalue(),mtime=0)

class FinalAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.vault=self.root/'vault.enc'
        for key,value in {'BASE':self.root,'SOURCE_DIR':self.root/'source','VAULT_FILE':self.vault,'LOG_FILE':self.root/'log','DECRYPTED_DIR':self.root/'decrypted'}.items():
            patch=mock.patch.object(v,key,value);patch.start();self.addCleanup(patch.stop)
        patch=mock.patch.object(v,'_get_kdf_params',return_value=KDF);patch.start();self.addCleanup(patch.stop)
        patch=mock.patch.object(v,'_log');patch.start();self.addCleanup(patch.stop)
    def test_missing_rebuild_source_has_clean_failure(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(v.rebuild_mode(self.root/'new.enc'))
        self.assertFalse((self.root/'new.enc').exists())
    def test_single_slot_rebuild_reserves_edit_headroom_and_preserves_original(self):
        original=v._pack_vault_v3('old',archive(b'public fixture'),kdf=KDF);self.vault.write_bytes(original)
        output=self.root/'new.enc'
        with mock.patch.object(v,'getpass',side_effect=['old','','new','new']),mock.patch('builtins.input',side_effect=['COPY','n']),contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(v.rebuild_mode(output))
        self.assertEqual(original,self.vault.read_bytes());self.assertGreaterEqual(v.slot_capacity(output.read_bytes(),0),4096)
    def test_hide_unhide_plan_requires_actual_carrier_selection(self):
        self.vault.write_bytes(v._pack_vault_v3('fixture',archive(b'a'),kdf=KDF))
        for mode in ('hide','unhide'):
            with self.subTest(mode=mode):
                result=v.collect_operation_plan(mode,self.vault,output_path=self.root/'output.enc')
                self.assertFalse(result['ok']);self.assertFalse(result['target_validated'])
                self.assertIn('exact_cover_or_carrier_required',result['errors'])
    def test_plan_member_budget_counts_directories(self):
        folder=self.root/'source';folder.mkdir();(folder/'a').mkdir();(folder/'b').mkdir()
        with mock.patch.object(v,'MAX_ARCHIVE_MEMBERS',2):
            result=v.collect_operation_plan('encrypt',inputs=[folder],output_path=self.root/'new.enc')
        self.assertFalse(result['ok']);self.assertIn('archive_budget_exceeded',result['errors'])
    def test_memory_view_uses_archive_budget_before_interaction(self):
        with mock.patch.object(v,'MAX_ARCHIVE_BYTES',2),mock.patch('builtins.input',side_effect=AssertionError('no interaction')),contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(v.VaultOperationError,'archive_budget_exceeded'):v._view_in_memory(archive(b'long public fixture'))
    @unittest.skipUnless(os.name=='nt','exclusive handle cleanup is Windows-specific')
    def test_snapshot_cleanup_same_size_modification_is_preserved(self):
        source=self.root/'source.txt';source.write_bytes(b'original')
        _,_,snapshots=v.archive_explicit_inputs([source])
        timestamp=source.stat().st_mtime_ns
        source.write_bytes(b'changed!');os.utime(source,ns=(timestamp,timestamp))
        preserved=v.cleanup_archived_snapshot(snapshots)
        self.assertEqual([source],preserved);self.assertEqual(b'changed!',source.read_bytes())
    @unittest.skipUnless(os.name=='nt','exclusive handle cleanup is Windows-specific')
    def test_snapshot_cleanup_preserves_open_writer(self):
        source=self.root/'source.txt';source.write_bytes(b'public fixture')
        _,_,snapshots=v.archive_explicit_inputs([source])
        with source.open('r+b') as writer:
            preserved=v.cleanup_archived_snapshot(snapshots)
            self.assertEqual([source],preserved)
            self.assertEqual(b'public fixture',writer.read())
        self.assertTrue(source.exists())
    @unittest.skipUnless(os.name=='nt','exclusive handle cleanup is Windows-specific')
    def test_snapshot_cleanup_refuses_renamed_replacement(self):
        source=self.root/'source.txt';source.write_bytes(b'public fixture')
        _,_,snapshots=v.archive_explicit_inputs([source]);original=self.root/'saved.txt';source.rename(original)
        source.write_bytes(b'public fixture')
        self.assertEqual([source],v.cleanup_archived_snapshot(snapshots))
        self.assertTrue(original.exists());self.assertTrue(source.exists())
    @unittest.skipUnless(os.name=='nt','exclusive handle cleanup is Windows-specific')
    def test_snapshot_cleanup_refuses_hardlinked_input(self):
        source=self.root/'source.txt';source.write_bytes(b'public fixture');alias=self.root/'alias.txt';os.link(source,alias)
        _,_,snapshots=v.archive_explicit_inputs([source])
        self.assertEqual([source],v.cleanup_archived_snapshot(snapshots));self.assertTrue(alias.exists());self.assertTrue(source.exists())
    @unittest.skipUnless(os.name=='nt','exclusive handle cleanup is Windows-specific')
    def test_snapshot_cleanup_fdopen_failure_releases_exclusive_handle(self):
        source=self.root/'source.txt';source.write_bytes(b'public fixture')
        _,_,snapshots=v.archive_explicit_inputs([source])
        with mock.patch.object(v.os,'fdopen',side_effect=OSError('fictional wrapper failure')):
            self.assertEqual([source],v.cleanup_archived_snapshot(snapshots))
        # This would fail with a sharing violation if the exclusive handle leaked.
        with source.open('r+b') as stream:
            self.assertEqual(b'public fixture',stream.read())

    @unittest.skipUnless(os.name=='nt','exclusive handle cleanup is Windows-specific')
    def test_snapshot_cleanup_deletes_same_verified_handle(self):
        source=self.root/'source.txt';source.write_bytes(b'public fixture')
        _,_,snapshots=v.archive_explicit_inputs([source])
        with mock.patch.object(Path,'unlink',side_effect=AssertionError('do not reselect a pathname')):
            self.assertEqual([],v.cleanup_archived_snapshot(snapshots))
        self.assertFalse(source.exists())

if __name__=='__main__':unittest.main()
