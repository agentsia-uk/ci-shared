"""Validate a reader lock and immutable archive bytes; this does not authenticate a release."""
from dataclasses import dataclass
import hashlib
from importlib.metadata import version
import json
import math
import re

MAX_MANIFEST_BYTES = 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_READER_FILES = 512
MAX_READER_BYTES = 32 * 1024 * 1024
MAX_EXPANDED_BYTES = 1024 * 1024 * 1024
PLATFORMS = frozenset({'linux-x86_64', 'linux-aarch64', 'macos-arm64'})
ASSET_NAMES = {platform: 'code_health/readers-' + platform + '.tar.zst' for platform in PLATFORMS}
SHA256 = re.compile(r'[0-9a-f]{64}\Z')
VERSION = re.compile(r'[0-9]+(?:\.[0-9]+)+\Z')


@dataclass(frozen=True)
class ReaderArchive:
    platform: str
    url: str
    sha256: str
    size: int


@dataclass(frozen=True)
class ReaderLock:
    version: str
    manifest_sha256: str
    archives: tuple[ReaderArchive, ...]


def _json(raw: bytes):
    if not isinstance(raw, bytes) or len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError('reader metadata exceeds its size limit')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate reader metadata key')
            result[key] = value
        return result
    def finite(value):
        result = float(value)
        if not math.isfinite(result):
            raise ValueError('non-finite number')
        return result
    try:
        return json.loads(raw, object_pairs_hook=unique, parse_float=finite,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError('non-finite number')))
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ValueError('invalid reader metadata') from error



def locked_package_version(requirements_raw: bytes) -> str:
    if not isinstance(requirements_raw, bytes) or len(requirements_raw) > MAX_MANIFEST_BYTES:
        raise ValueError('invalid dependency lock')
    try:
        text = requirements_raw.decode('utf-8')
    except UnicodeError as error:
        raise ValueError('invalid dependency lock') from error
    versions = re.findall(r'^tree-sitter-language-pack==([0-9]+(?:\.[0-9]+)+)(?=\s|\\|$)', text, re.MULTILINE)
    if len(versions) != 1:
        raise ValueError('reader package is not uniquely pinned')
    return versions[0]


def required_grammars() -> set[str]:
    """Derive the full set from the independently selected, pinned scanner."""
    from desloppify.languages import available_langs
    from desloppify.languages._framework.treesitter import get_spec
    return {spec.grammar for language in available_langs() if (spec := get_spec(language)) is not None}


def verify_manifest(lock_raw: bytes, manifest_raw: bytes, *, package_version: str, grammars: set[str]) -> ReaderLock:
    """Check lock/manifest consistency; the caller must authenticate the lock's release."""
    lock, manifest = _json(lock_raw), _json(manifest_raw)
    if (not isinstance(lock, dict) or set(lock) != {'schemaVersion', 'package', 'version', 'manifestSha256', 'platforms'}
            or type(lock['schemaVersion']) is not int or lock['schemaVersion'] != 1
            or lock['package'] != 'tree-sitter-language-pack'
            or not isinstance(lock['version'], str) or not VERSION.fullmatch(lock['version'])
            or lock['version'] != package_version or not isinstance(lock['manifestSha256'], str)
            or not SHA256.fullmatch(lock['manifestSha256'])
            or hashlib.sha256(manifest_raw).hexdigest() != lock['manifestSha256']
            or not isinstance(lock['platforms'], dict) or set(lock['platforms']) != PLATFORMS):
        raise ValueError('invalid reader lock')
    if (not isinstance(manifest, dict) or manifest.get('version') != lock['version']
            or not isinstance(manifest.get('languages'), dict) or not isinstance(manifest.get('platforms'), dict)
            or not isinstance(manifest.get('groups'), dict)
            or not isinstance(grammars, set)
            or any(not isinstance(name, str) or not name for name in grammars)
            or not grammars <= set(manifest['languages'])):
        raise ValueError('reader manifest does not cover the pinned scanner')
    for name in grammars:
        item = manifest['languages'][name]
        if (not isinstance(item, dict) or not isinstance(item.get('group'), str)
                or type(item.get('size')) is not int or item['size'] < 0
                or not isinstance(manifest['groups'].get(item['group']), list)
                or name not in manifest['groups'][item['group']]):
            raise ValueError('reader language entry is invalid')
    archives = []
    for platform in sorted(PLATFORMS):
        entry = lock['platforms'][platform]
        expected_url = ('https://github.com/kreuzberg-dev/tree-sitter-language-pack/releases/download/v'
                        + lock['version'] + '/parsers-' + platform + '.tar.zst')
        if (not isinstance(entry, dict) or set(entry) != {'url', 'sha256', 'size'}
                or entry.get('url') != expected_url or not isinstance(entry.get('sha256'), str)
                or not SHA256.fullmatch(entry['sha256']) or type(entry.get('size')) is not int
                or not 0 < entry['size'] <= MAX_ARCHIVE_BYTES or manifest['platforms'].get(platform) != entry):
            raise ValueError('reader platform differs from the locked manifest')
        archives.append(ReaderArchive(platform, entry['url'], entry['sha256'], entry['size']))
    return ReaderLock(lock['version'], lock['manifestSha256'], tuple(archives))


def verify_archive(data: bytes, *, lock: ReaderLock, platform: str) -> bytes:
    """Return the same immutable bytes only when they match the authenticated lock."""
    if not isinstance(data, bytes) or not isinstance(lock, ReaderLock):
        raise ValueError('invalid reader archive input')
    selected = [entry for entry in lock.archives if entry.platform == platform]
    if (len(selected) != 1 or len(data) != selected[0].size or len(data) > MAX_ARCHIVE_BYTES
            or hashlib.sha256(data).hexdigest() != selected[0].sha256):
        raise ValueError('reader archive differs from the approved lock')
    return data


def verify_selected_manifest(lock_raw: bytes, manifest_raw: bytes) -> ReaderLock:
    return verify_manifest(lock_raw, manifest_raw, package_version=version('tree-sitter-language-pack'),
                           grammars=required_grammars())


def unpack_archive(data: bytes, *, lock: ReaderLock, platform: str, destination_fd: int) -> dict[str, str]:
    """Unpack verified readers into an empty private directory; caller must mount it read-only."""
    import io
    import os
    import stat
    import tarfile
    import zstandard

    verify_archive(data, lock=lock, platform=platform)
    if type(destination_fd) is not int or destination_fd < 0:
        raise ValueError('invalid reader destination')
    directory = os.fstat(destination_fd)
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_mode & 0o077
            or (hasattr(os, 'geteuid') and directory.st_uid != os.geteuid()) or os.listdir(destination_fd)):
        raise ValueError('reader destination must be an empty private directory')
    extension = 'dylib' if platform == 'macos-arm64' else 'so'
    filename = re.compile(r'libtree_sitter_[a-z0-9_]+\.' + extension + r'\Z')
    seen = {}
    total = 0
    class BoundedReader:
        def __init__(self, source):
            self.source = source
            self.remaining = MAX_EXPANDED_BYTES + MAX_READER_FILES * 4096 + 1024 * 1024
        def read(self, size=-1):
            size = self.remaining + 1 if size < 0 else min(size, self.remaining + 1)
            data = self.source.read(size)
            if len(data) > self.remaining:
                raise ValueError('reader archive expands beyond its limit')
            self.remaining -= len(data)
            return data
    with zstandard.ZstdDecompressor().stream_reader(io.BytesIO(data)) as decompressed:
        with tarfile.open(fileobj=BoundedReader(decompressed), mode='r|') as archive:
            for entry in archive:
                name = entry.name.removeprefix('./')
                if name in {'', '.'} and entry.isdir():
                    continue
                if (not entry.isfile() or not filename.fullmatch(name) or name in seen
                        or type(entry.size) is not int or not 0 < entry.size <= MAX_READER_BYTES
                        or len(seen) >= MAX_READER_FILES or total + entry.size > MAX_EXPANDED_BYTES):
                    raise ValueError('unsafe reader archive entry')
                total += entry.size
                stream = archive.extractfile(entry)
                if stream is None:
                    raise ValueError('reader archive entry is unreadable')
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                             dir_fd=destination_fd)
                digest = hashlib.sha256()
                remaining = entry.size
                try:
                    while remaining:
                        chunk = stream.read(min(remaining, 1024 * 1024))
                        if not chunk:
                            raise ValueError('reader archive entry is truncated')
                        digest.update(chunk)
                        view = memoryview(chunk)
                        while view:
                            count = os.write(fd, view)
                            if count <= 0:
                                raise ValueError('reader write made no progress')
                            view = view[count:]
                        remaining -= len(chunk)
                    os.fchmod(fd, 0o400)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                seen[name] = digest.hexdigest()
    if not seen:
        raise ValueError('reader archive contains no libraries')
    os.fsync(destination_fd)
    return dict(sorted(seen.items()))
