"""Data preservation and recovery regressions; only test-owned synthetic files."""
import contextlib
import gzip
import io
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock
import tarfile
import vault_tool as v

KDF=(1,1024,8,1)

def archive(entries):
    buf=io.BytesIO()
    with tarfile.open(fileobj=buf,mode='w') as t:
        for name,data in entries.items():
            m=tarfile.TarInfo(name);m.size=len(data);t.addfile(m,io.BytesIO(data))
    return gzip.compress(buf.getvalue(),mtime=0)

class RecoveryRegression(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.vault=self.root/'vault.enc'
        for name,path in [('BASE',self.root),('VAULT_FILE',self.vault),('SOURCE_DIR',self.root/'source'),('DECOY_SOURCE_DIR',self.root/'decoy_source'),('DECRYPTED_DIR',self.root/'decrypted'),('LOG_FILE',self.root/'vault.log')]:
            patch=mock.patch.object(v,name,path);patch.start();self.addCleanup(patch.stop)
        p=mock.patch.object(v,'_get_kdf_params',return_value=KDF);p.start();self.addCleanup(p.stop)
        p=mock.patch.object(v,'_log');p.start();self.addCleanup(p.stop)
    def dual(self):
        visible=v.reserve_edit_capacity(archive({'visible.txt':b'public fixture'}))
        hidden=archive({'hidden.txt':b'other synthetic fixture'})
        return v._pack_vault_v3('hidden-pass',hidden,decoy_password='visible-pass',decoy_plaintext=visible,kdf=KDF)
    def test_password_change_preserves_other_slot_for_each_password(self):
        for password,other,layer in [('visible-pass','hidden-pass',0),('hidden-pass','visible-pass',1)]:
            with self.subTest(layer=layer):
                original=self.dual();self.vault.write_bytes(original)
                before_other,other_layer=v._decrypt_blob(other,original)
                with mock.patch.object(v,'getpass',side_effect=[password,'new-pass','new-pass']),mock.patch('builtins.input',return_value='n'),contextlib.redirect_stdout(io.StringIO()):
                    self.assertTrue(v.change_password_mode())
                after=self.vault.read_bytes();end=93+struct.unpack('>Q',original[85:93])[0]
                self.assertEqual(original[end:] if layer==0 else original[:end],after[end:] if layer==0 else after[:end])
                self.assertEqual(bytes(before_other),bytes(v._decrypt_blob(other,after)[0]))
                self.assertEqual(layer,v._decrypt_blob('new-pass',after)[1])
    def test_merge_preserves_other_slot_without_plaintext_staging(self):
        original=self.dual();self.vault.write_bytes(original)
        added=self.root/'new.bin';added.write_bytes(bytes(range(256)))
        with mock.patch.object(v,'getpass',return_value='visible-pass'),mock.patch('builtins.input',side_effect=['',str(added),'']),contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(v.add_files_mode())
        end=93+struct.unpack('>Q',original[85:93])[0]
        self.assertEqual(original[end:],self.vault.read_bytes()[end:])
        self.assertEqual([],list(v.SOURCE_DIR.iterdir()))
        opened,_=v._decrypt_blob('visible-pass',self.vault.read_bytes())
        with tarfile.open(fileobj=io.BytesIO(opened),mode='r:*') as t:self.assertEqual(t.extractfile('new.bin').read(),added.read_bytes())
    def test_oversized_edit_keeps_both_original_slots(self):
        original=self.dual();self.vault.write_bytes(original)
        with self.assertRaisesRegex(v.VaultOperationError,'slot_capacity_exceeded'):
            v.replace_unlocked_slot(original,'visible-pass',None,0,b'x'*(v.slot_capacity(original,0)+1))
        self.assertEqual(original,self.vault.read_bytes())
    def test_new_archive_has_edit_headroom_and_sources_survive(self):
        v.SOURCE_DIR.mkdir();source=v.SOURCE_DIR/'a.txt';source.write_bytes(b'a')
        with mock.patch.object(v,'getpass',side_effect=['p','p']),mock.patch('builtins.input',return_value='n'),contextlib.redirect_stdout(io.StringIO()):self.assertTrue(v.encrypt_mode())
        self.assertEqual(b'a',source.read_bytes());self.assertGreaterEqual(v.slot_capacity(self.vault.read_bytes(),0),4096)
    def test_snapshot_cleanup_preserves_new_and_changed_files(self):
        source=self.root/'source';source.mkdir();a=source/'a';b=source/'b';a.write_bytes(b'a');b.write_bytes(b'b')
        payload,count,snapshot=v.archive_explicit_inputs([source])
        b.write_bytes(b'changed');c=source/'c';c.write_bytes(b'new')
        preserved=v.cleanup_archived_snapshot(snapshot)
        self.assertFalse(a.exists());self.assertEqual(b'changed',b.read_bytes());self.assertEqual(b'new',c.read_bytes());self.assertIn(b,preserved)
    def test_first_file_export_failure_reports_plaintext_write_and_no_final_partial(self):
        dest=self.root/'export';payload=archive({'entry.txt':b'fictional bytes'})
        with mock.patch.object(v,'_hash_file',side_effect=OSError('synthetic readback failure')):
            with self.assertRaises(v.VaultOperationError) as raised:v.export_archive(payload,dest)
        self.assertTrue(raised.exception.plaintext_written);self.assertEqual(0,raised.exception.count)
        self.assertFalse((dest/'entry.txt').exists());self.assertEqual([],list(dest.iterdir()))
    def test_export_retry_verifies_identical_and_reports_conflicts(self):
        payload=archive({'one':b'1','two':b'2'});dest=self.root/'out'
        first=v.export_archive(payload,dest);self.assertEqual(2,first['count'])
        second=v.export_archive(payload,dest);self.assertEqual(2,second['already_count']);self.assertFalse(second['plaintext_written_to_disk'])
        (dest/'two').write_bytes(b'KEEP');third=v.export_archive(payload,dest)
        self.assertEqual('partial',third['status']);self.assertEqual(1,third['conflict_count']);self.assertEqual(b'KEEP',(dest/'two').read_bytes())
    def test_export_concurrent_target_never_overwrites_or_changes_time(self):
        dest=self.root/'out';actual=v.publish_no_replace;stamp=1234567890
        def concurrent(candidate,target):
            Path(target).write_bytes(b'other writer');os.utime(target,(stamp,stamp));return actual(candidate,target)
        with mock.patch.object(v,'publish_no_replace',side_effect=concurrent):result=v.export_archive(archive({'a':b'1'}),dest)
        self.assertEqual(1,result['conflict_count']);self.assertEqual(b'other writer',(dest/'a').read_bytes());self.assertEqual(stamp,int((dest/'a').stat().st_mtime))
    def test_commit_failed_final_verification_restores_original(self):
        self.vault.write_bytes(b'old');calls=[]
        def verify(data):
            calls.append(1)
            if len(calls)==3:raise ValueError('synthetic verification failure')
        with self.assertRaises(v.VaultOperationError):v.commit_ciphertext(self.vault,b'old',b'new',verify)
        self.assertEqual(b'old',self.vault.read_bytes());self.assertEqual([self.vault],list(self.root.iterdir()))
    def test_new_target_failed_final_verification_is_removed(self):
        calls=[]
        def verify(data):
            calls.append(1)
            if len(calls)==3:raise ValueError('synthetic failure')
        with self.assertRaises(v.VaultOperationError):v.commit_ciphertext(self.vault,None,b'new',verify)
        self.assertFalse(self.vault.exists())
    def test_changed_target_preserved_before_commit(self):
        self.vault.write_bytes(b'concurrent')
        with self.assertRaisesRegex(v.VaultOperationError,'vault_changed'):v.commit_ciphertext(self.vault,b'old',b'new',lambda data:None)
        self.assertEqual(b'concurrent',self.vault.read_bytes())
    def test_invalid_kdf_rejected_without_derivation(self):
        for params in [(1,1024,0,1),(1,1024,8,1000000),(2,1000000,65536,4),(1,3,8,1),(2,3,8,8)]:
            with self.subTest(params=params),self.assertRaises(ValueError):v._validate_container_kdf(*params)
    def test_legacy_work_budget_checked_before_real_kdf(self):
        with mock.patch.object(v,'SCRYPT_N',1024):blob=v._pack_vault('p',b'synthetic')
        malformed=bytearray(blob);malformed[16:20]=struct.pack('>I',1000000)
        with mock.patch.object(v,'derive_key_scrypt',side_effect=AssertionError('must not derive')):
            with self.assertRaises(ValueError):v._decrypt_blob('p',malformed)
    def test_exact_missing_vault_plan_does_not_use_default(self):
        self.vault.write_bytes(self.dual());missing=self.root/'missing.enc'
        result=v.collect_vault_plan(vault_file=str(missing))
        self.assertEqual(str(missing),result['assessment']['vault']['vault_file']);self.assertFalse(result['assessment']['vault']['exists'])
    def test_credential_plan_reports_shared_header_and_new_copy(self):
        self.vault.write_bytes(self.dual());plan=v.collect_credential_plan(str(self.vault),'keyfile')
        self.assertTrue(plan['requires_new_output']);self.assertEqual('unknown',plan['other_slot_presence']);self.assertFalse(plan['credentials_verified'])
    def test_recovery_environment_self_test_is_synthetic_and_zero_file_write(self):
        with mock.patch('builtins.open',side_effect=AssertionError('no files')):result=v.collect_recovery_check(self_test=True)
        self.assertTrue(result['self_test_passed']);self.assertFalse(result['real_vault_decrypted'])
    def test_backup_never_replaces_previous_backup(self):
        original=self.dual();self.vault.write_bytes(original);existing=self.vault.with_suffix('.enc.bak');existing.write_bytes(b'keep')
        created=v.preserve_ciphertext_backup(self.vault,original)
        self.assertEqual(b'keep',existing.read_bytes());self.assertEqual(original,created.read_bytes())
    def test_archive_budget_checked_before_member_read(self):
        payload=archive({'a':b'12345'})
        with mock.patch.object(v,'MAX_ARCHIVE_BYTES',4):
            with self.assertRaises(v.VaultOperationError):v.export_archive(payload,self.root/'out')
    def test_rebuild_selected_slots_keeps_original_and_creates_verified_new_copy(self):
        original=self.dual();self.vault.write_bytes(original);output=self.root/'new.enc'
        with mock.patch.object(v,'getpass',side_effect=['visible-pass','hidden-pass','new-visible','new-visible','new-hidden','new-hidden']),mock.patch('builtins.input',return_value='n'),contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(v.rebuild_mode(output))
        self.assertEqual(original,self.vault.read_bytes());self.assertEqual(0,v._decrypt_blob('new-visible',output.read_bytes())[1]);self.assertEqual(1,v._decrypt_blob('new-hidden',output.read_bytes())[1])

if __name__=='__main__':unittest.main()
