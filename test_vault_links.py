"""PCConfig trusted vault links; only synthetic registries and temp junctions."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import vault_tool as v

if os.name == 'nt':
    import _winapi


def _registry_document(links, schema=v.PERSONAL_VAULT_LINKS_SCHEMA):
    return json.dumps({'schema': schema, 'written_utc': '2026-10-01T00:00:00Z', 'links': links})


@unittest.skipUnless(os.name == 'nt', 'Windows junctions')
class TrustedVaultLinkTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(os.path.abspath(self.tmp.name))
        self.registry = self.root / 'vault-links.json'
        patch = mock.patch.object(v, 'PERSONAL_VAULT_LINKS_REGISTRY', self.registry)
        patch.start()
        self.addCleanup(patch.stop)

    def junction(self, link, target):
        target.mkdir(parents=True, exist_ok=True)
        _winapi.CreateJunction(str(target), str(link))
        # Cleanups run LIFO: the junction itself goes before the temp tree,
        # and os.rmdir never recurses into the target.
        self.addCleanup(lambda: os.path.lexists(link) and os.rmdir(link))
        return link

    def register(self, links, schema=v.PERSONAL_VAULT_LINKS_SCHEMA):
        self.registry.write_text(_registry_document(links, schema), encoding='utf-8')

    def assertRejected(self, path):
        with self.assertRaises(v.VaultOperationError) as caught:
            v._reject_reparse_chain(path)
        self.assertEqual('reparse_point_rejected', caught.exception.code)

    def test_registered_junction_with_matching_target_is_allowed(self):
        link = self.junction(self.root / 'Pictures', self.root / 'vault' / 'Pictures')
        target = os.readlink(link)
        self.assertTrue(target.startswith('\\\\?\\'))
        # Case and the \\?\ prefix may differ between the registry and readlink.
        self.register([{'path': str(link).upper(), 'target': target[4:].lower()}])
        nested = link / 'album' / 'a.jpg'
        nested.parent.mkdir()
        nested.write_bytes(b'fixture')
        self.assertEqual(nested, v._reject_reparse_chain(nested))
        self.assertEqual(link, v._reject_reparse_chain(link))
        payload, count, _ = v.archive_explicit_inputs([link / 'album'])
        self.assertEqual(1, count)
        self.assertTrue(payload)

    def test_unusable_registry_keeps_rejecting_every_reparse_point(self):
        link = self.junction(self.root / 'Pictures', self.root / 'vault' / 'Pictures')
        nested = link / 'a.jpg'
        nested.write_bytes(b'fixture')
        good_entry = {'path': str(link), 'target': os.readlink(link)}
        cases = {
            'absent': None,
            'empty': b'',
            'corrupt': b'{not json',
            'wrong-schema': _registry_document([good_entry], 'pcconfig.personal-vault-links.v2').encode(),
            'missing-schema': json.dumps({'links': [good_entry]}).encode(),
            'links-not-list': json.dumps({'schema': v.PERSONAL_VAULT_LINKS_SCHEMA, 'links': good_entry}).encode(),
            'entry-not-object': _registry_document([good_entry, 'x']).encode(),
            'target-not-string': _registry_document([{'path': str(link), 'target': 1}]).encode(),
            'relative-entry': _registry_document([good_entry, {'path': 'Videos', 'target': 'x'}]).encode(),
            'not-object': b'[]',
        }
        for name, content in cases.items():
            with self.subTest(name):
                self.registry.unlink(missing_ok=True)
                if content is not None:
                    self.registry.write_bytes(content)
                self.assertRejected(nested)
                self.assertRejected(link)

    def test_unregistered_and_mismatched_junctions_stay_rejected(self):
        registered = self.junction(self.root / 'Pictures', self.root / 'vault' / 'Pictures')
        unregistered = self.junction(self.root / 'Videos', self.root / 'vault' / 'Videos')
        mismatched = self.junction(self.root / 'Music', self.root / 'elsewhere' / 'Music')
        self.register([
            {'path': str(registered), 'target': os.readlink(registered)},
            {'path': str(mismatched), 'target': str(self.root / 'vault' / 'Music')},
        ])
        v._reject_reparse_chain(registered / 'a.jpg')
        self.assertRejected(unregistered / 'a.jpg')
        self.assertRejected(mismatched / 'a.jpg')

    def test_unregistered_junction_below_trusted_link_is_still_rejected(self):
        root = self.junction(self.root / 'PersonalData', self.root / 'vault' / 'PersonalData')
        self.register([{'path': str(root), 'target': os.readlink(root)}])
        (root / 'records').mkdir()
        inner = self.junction(root / 'records' / 'case', self.root / 'outside' / 'case')
        (inner / 'a.txt').write_bytes(b'fixture')
        v._reject_reparse_chain(root / 'records')
        self.assertRejected(inner / 'a.txt')
        with self.assertRaises(v.VaultOperationError) as caught:
            v.archive_explicit_inputs([root / 'records'])
        self.assertEqual('reparse_point_rejected', caught.exception.code)

    def test_registered_symlink_stays_rejected(self):
        target = self.root / 'vault' / 'Pictures'
        target.mkdir(parents=True)
        link = self.root / 'Pictures'
        try:
            link.symlink_to(target, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f'symlink creation unavailable: {exc}')
        self.addCleanup(link.rmdir)
        self.register([{'path': str(link), 'target': os.readlink(link)}])
        self.assertRejected(link / 'a.jpg')

    def test_symlink_reparse_tag_is_never_trusted(self):
        link = self.root / 'Pictures'
        target = '\\\\?\\E:\\.PersonalVault\\Media\\Pictures'
        info = SimpleNamespace(st_mode=0o040777, st_reparse_tag=0xA000000C)  # IO_REPARSE_TAG_SYMLINK
        trusted = {v._vault_link_path_key(str(link)): v._vault_link_target_key(target)}
        with mock.patch.object(v.os, 'readlink', return_value=target):
            self.assertFalse(v._is_trusted_vault_link(link, info, trusted))

    def test_registered_volume_mount_point_is_allowed_only_for_its_volume(self):
        # Folder-mounted volumes need administrator rights; simulate the OS view.
        mount = self.root / 'PersonalData'
        (mount / 'records').mkdir(parents=True)
        volume = '\\\\?\\Volume{00000000-0000-0000-0000-00000000000a}\\'
        self.register([{'path': str(mount), 'target': volume}])
        real_lstat = Path.lstat

        def fake_lstat(self_path, *args, **kwargs):
            info = real_lstat(self_path, *args, **kwargs)
            if os.path.normcase(str(self_path)) != os.path.normcase(str(mount)):
                return info
            return SimpleNamespace(
                st_mode=info.st_mode,
                st_file_attributes=info.st_file_attributes | 0x400,
                st_reparse_tag=v.IO_REPARSE_TAG_MOUNT_POINT,
            )

        actual = {'target': volume}
        with mock.patch.object(Path, 'lstat', fake_lstat), \
                mock.patch.object(v.os, 'readlink', lambda _: actual['target']):
            v._reject_reparse_chain(mount / 'records' / 'a.txt')
            actual['target'] = '\\\\?\\Volume{00000000-0000-0000-0000-00000000000b}\\'
            self.assertRejected(mount / 'records' / 'a.txt')


if __name__ == '__main__':
    unittest.main()
