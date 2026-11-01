import subprocess
import tempfile
import unittest
import hashlib
import io
import json
import tarfile
from pathlib import Path
from unittest.mock import patch

from code_health.build_release_bundle import ReaderRedirect, build_bundle, read_reader_archives, runtime_files
from code_health.release_bundle import read_bundle
from code_health.readers_lock import ASSET_NAMES
from tests.test_readers_lock import fixture as readers_fixture, encoded
from code_health.qualification_candidate import candidate_snapshot
from code_health.qualification_results import collect_bundle_results

FILES = {'code_health/cli.py', 'code_health/policy.json', 'code_health/requirements.lock',
         'code_health/readers-lock.json', 'code_health/readers-upstream.json'} | set(ASSET_NAMES.values())


class BuildReleaseBundleTests(unittest.TestCase):
    def setUp(self):
        grammars = patch('code_health.build_release_bundle.required_grammars', return_value={'tsx'})
        grammars.start()
        self.addCleanup(grammars.stop)
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.addCleanup(self.directory.cleanup)
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        subprocess.run(['git', 'config', 'user.name', 'fixture'], cwd=self.root, check=True)
        subprocess.run(['git', 'config', 'user.email', 'fixture@example.test'], cwd=self.root, check=True)
        (self.root / 'code_health').mkdir()
        (self.root / 'code_health/cli.py').write_text('committed')
        (self.root / 'code_health/policy.json').write_text('{"desloppifyVersion":"1.0","readerMetadataVersion":1}')
        (self.root / 'code_health/requirements.lock').write_text('tree-sitter-language-pack==1.6.2\n')
        lock, upstream, self.payloads = readers_fixture()
        (self.root / 'code_health/readers-lock.json').write_bytes(encoded(lock))
        (self.root / 'code_health/readers-upstream.json').write_bytes(encoded(upstream))
        subprocess.run(['git', 'add', '.'], cwd=self.root, check=True)
        subprocess.run(['git', 'commit', '-qm', 'fixture'], cwd=self.root, check=True)
        self.commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=self.root, text=True).strip()

    def test_deterministic_bundle_reads_committed_bytes(self):
        (self.root / 'code_health/cli.py').write_text('uncommitted')
        self.assertEqual(runtime_files(self.root, self.commit), FILES)
        data = build_bundle(self.root, self.commit, FILES, reader_archives=self.payloads)
        self.assertEqual(data, build_bundle(self.root, self.commit, FILES, reader_archives=self.payloads))
        manifest, files, _ = read_bundle(data, policy_commit=self.commit, allowed_files=FILES)
        self.assertEqual(files['code_health/cli.py'], b'committed')
        self.assertEqual(manifest['desloppifyVersion'], '1.0')

    def test_reader_metadata_must_be_complete_and_match_the_dependency_lock(self):
        with self.assertRaisesRegex(ValueError, 'missing or undeclared'):
            build_bundle(self.root, self.commit, FILES - {'code_health/readers-upstream.json'}, reader_archives=self.payloads)
        (self.root / 'code_health/requirements.lock').write_text('tree-sitter-language-pack==1.6.3\n')
        subprocess.run(['git', 'add', 'code_health/requirements.lock'], cwd=self.root, check=True)
        subprocess.run(['git', 'commit', '-qm', 'mismatched reader version'], cwd=self.root, check=True)
        changed = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=self.root, text=True).strip()
        with self.assertRaises(ValueError):
            build_bundle(self.root, changed, FILES, reader_archives=self.payloads)

    def test_release_builder_refuses_missing_supported_grammar(self):
        with patch('code_health.build_release_bundle.required_grammars', return_value={'tsx', 'nim'}):
            with self.assertRaisesRegex(ValueError, 'does not cover'):
                build_bundle(self.root, self.commit, FILES, reader_archives=self.payloads)

    def test_release_requires_every_exact_reader_archive(self):
        for archives in (None, {k: v for k, v in self.payloads.items() if k != 'linux-x86_64'},
                         {**self.payloads, 'linux-x86_64': b'changed'}):
            with self.subTest(archives=archives), self.assertRaises(ValueError):
                build_bundle(self.root, self.commit, FILES, reader_archives=archives)

    def test_release_downloads_and_verifies_the_locked_archives(self):
        def open_archive(url, *, timeout):
            platform = url.rsplit('parsers-', 1)[1].removesuffix('.tar.zst')
            self.assertEqual(timeout, 60)
            return io.BytesIO(self.payloads[platform])
        with patch('code_health.build_release_bundle.urllib.request.build_opener') as opener:
            opener.return_value.open.side_effect = open_archive
            data = build_bundle(self.root, self.commit, FILES, download_readers=True)
            read_bundle(data, policy_commit=self.commit, allowed_files=FILES)
            opener.return_value.open.return_value = io.BytesIO(b'wrong')
            opener.return_value.open.side_effect = None
            with self.assertRaisesRegex(ValueError, 'approved lock'):
                build_bundle(self.root, self.commit, FILES, download_readers=True)

    def test_reader_download_refuses_untrusted_redirects(self):
        redirect = ReaderRedirect()
        for url in ('http://github.com/file', 'https://example.com/file',
                    'https://github.com@evil.example/file', 'https://github.com:444/file'):
            with self.subTest(url=url), self.assertRaisesRegex(ValueError, 'redirect is not trusted'):
                redirect.redirect_request(None, None, 302, '', {}, url)

    def test_reader_archive_input_refuses_symlinks(self):
        directory = self.root / 'readers'
        directory.mkdir()
        for platform, data in self.payloads.items():
            (directory / f'parsers-{platform}.tar.zst').write_bytes(data)
        self.assertEqual(read_reader_archives(directory), self.payloads)
        path = directory / 'parsers-linux-x86_64.tar.zst'
        path.unlink()
        path.symlink_to(directory / 'parsers-linux-aarch64.tar.zst')
        with self.assertRaises(OSError):
            read_reader_archives(directory)

    def test_rehashed_bundle_index_cannot_hide_a_changed_reader(self):
        data = build_bundle(self.root, self.commit, FILES, reader_archives=self.payloads)
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
            contents = {entry.name: archive.extractfile(entry).read() for entry in archive}
        name = ASSET_NAMES['linux-x86_64']
        contents[name] = b'x' * len(contents[name])
        manifest = json.loads(contents['release.json'])
        entry = next(item for item in manifest['files'] if item['path'] == name)
        entry['sha256'] = hashlib.sha256(contents[name]).hexdigest()
        contents['release.json'] = json.dumps(manifest).encode()
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w') as archive:
            for filename, content in contents.items():
                item = tarfile.TarInfo(filename)
                item.size = len(content)
                archive.addfile(item, io.BytesIO(content))
        with self.assertRaisesRegex(ValueError, 'invalid reader metadata'):
            read_bundle(output.getvalue(), policy_commit=self.commit, allowed_files=FILES)

    def test_legacy_commits_without_reader_metadata_remain_buildable(self):
        for name in ('readers-lock.json', 'readers-upstream.json'):
            (self.root / 'code_health' / name).unlink()
        (self.root / 'code_health/policy.json').write_text('{"desloppifyVersion":"1.0"}')
        subprocess.run(['git', 'add', '-A'], cwd=self.root, check=True)
        subprocess.run(['git', 'commit', '-qm', 'legacy fixture'], cwd=self.root, check=True)
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=self.root, text=True).strip()
        selected = runtime_files(self.root, commit)
        self.assertNotIn('code_health/readers-lock.json', selected)
        data = build_bundle(self.root, commit, selected)
        read_bundle(data, policy_commit=commit, allowed_files=selected)

    def test_qualification_snapshot_uses_exact_verified_bundle_and_cleans_up(self):
        data = build_bundle(self.root, self.commit, FILES, reader_archives=self.payloads)
        digest = hashlib.sha256(data).hexdigest()
        (self.root / 'code_health/cli.py').write_text('uncommitted')
        with candidate_snapshot(data, expected_sha256=digest, policy_commit=self.commit, allowed_files=FILES) as snapshot:
            self.assertEqual((snapshot / 'code_health/cli.py').read_bytes(), b'committed')
            self.assertEqual((snapshot / 'code_health/cli.py').stat().st_mode & 0o777, 0o644)
            self.assertEqual(snapshot.stat().st_mode & 0o777, 0o755)
        self.assertFalse(snapshot.exists())
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            with candidate_snapshot(data, expected_sha256='0' * 64, policy_commit=self.commit, allowed_files=FILES):
                pass
        with self.assertRaises(ValueError):
            with candidate_snapshot(data, expected_sha256=digest, policy_commit='0' * 40, allowed_files=FILES):
                pass

    def test_collection_uses_bundle_snapshot_and_refuses_digest_mismatch(self):
        data = build_bundle(self.root, self.commit, FILES, reader_archives=self.payloads)
        digest = hashlib.sha256(data).hexdigest()
        seen = []
        def runner(*, candidate, case_id, **_kwargs):
            self.assertEqual((candidate / 'code_health/cli.py').read_bytes(), b'committed')
            seen.append(candidate)
            return {'schemaVersion': 1, 'caseId': case_id, 'outcome': 'returned', 'value': None}
        result = collect_bundle_results(bundle=data, expected_sha256=digest, policy_commit=self.commit,
                                        allowed_files=FILES, image=None, bridge=None, run_id=1, run_attempt=1, runner=runner)
        self.assertTrue(result)
        self.assertTrue(seen)
        self.assertTrue(all(candidate == seen[0] for candidate in seen))
        self.assertFalse(seen[0].exists())
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            collect_bundle_results(bundle=data, expected_sha256='0' * 64, policy_commit=self.commit,
                                   allowed_files=FILES, image=None, bridge=None, run_id=1, run_attempt=1, runner=runner)

    def test_rejects_missing_files_and_invalid_refs(self):
        for commit, paths in [(self.commit, FILES | {'code_health/missing.py'}), ('main', FILES),
                              (self.commit, FILES | {'code_health/../outside'})]:
            with self.subTest(commit=commit, paths=paths), self.assertRaises(ValueError):
                build_bundle(self.root, commit, paths, reader_archives=self.payloads)

    def test_rejects_committed_symlink(self):
        (self.root / 'code_health/cli.py').unlink()
        (self.root / 'code_health/cli.py').symlink_to('/etc/passwd')
        subprocess.run(['git', 'add', '.'], cwd=self.root, check=True)
        subprocess.run(['git', 'commit', '-qm', 'symlink'], cwd=self.root, check=True)
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=self.root, text=True).strip()
        with self.assertRaises(ValueError):
            build_bundle(self.root, commit, FILES, reader_archives=self.payloads)

    def test_runtime_selection_ignores_uncommitted_and_non_runtime_files(self):
        (self.root / 'code_health/uncommitted.py').write_text('ignored')
        (self.root / 'code_health/notes.txt').write_text('ignored')
        subprocess.run(['git', 'add', 'code_health/notes.txt'], cwd=self.root, check=True)
        subprocess.run(['git', 'commit', '-qm', 'notes'], cwd=self.root, check=True)
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=self.root, text=True).strip()
        self.assertEqual(runtime_files(self.root, commit), FILES)

    def test_ignores_poisoned_git_path_and_inherited_git_directory(self):
        fake_bin = self.root / 'bin'
        fake_bin.mkdir()
        marker = self.root / 'fake-git-called'
        fake_git = fake_bin / 'git'
        fake_git.write_text(f'#!/bin/sh\ntouch "{marker}"\nexit 93\n')
        fake_git.chmod(0o755)
        with patch.dict('os.environ', {'PATH': str(fake_bin), 'GIT_DIR': str(self.root / 'wrong')}):
            data = build_bundle(self.root, self.commit, FILES, reader_archives=self.payloads)
        self.assertFalse(marker.exists())
        self.assertEqual(read_bundle(data, policy_commit=self.commit, allowed_files=FILES)[1]['code_health/cli.py'], b'committed')

    def test_ignores_git_replace_refs_when_reading_the_selected_commit(self):
        (self.root / 'code_health/cli.py').write_text('replacement')
        subprocess.run(['git', 'add', 'code_health/cli.py'], cwd=self.root, check=True)
        subprocess.run(['git', 'commit', '-qm', 'replacement'], cwd=self.root, check=True)
        replacement = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=self.root, text=True).strip()
        subprocess.run(['git', 'replace', self.commit, replacement], cwd=self.root, check=True)
        data = build_bundle(self.root, self.commit, runtime_files(self.root, self.commit), reader_archives=self.payloads)
        self.assertEqual(read_bundle(data, policy_commit=self.commit, allowed_files=FILES)[1]['code_health/cli.py'], b'committed')
