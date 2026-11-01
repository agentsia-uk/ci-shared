"""Apply the reviewed TypeScript coverage correction to the pinned scanner."""
import hashlib
from pathlib import Path
import importlib.util
import os
import tempfile

ORIGINAL_SHA256 = 'ab59a286ef8165fb8c812d894c1e1db6a6facca547a4a32e96eb20a5cfb3cd1f'
PATCH_ID = 'typescript-test-mapping-v1'
PATCHED_SHA256 = 'c3cc9f3d130093b6e9a289c67893e25fbcef44a3091bdd7bf081069dbee0d28f'
OLD = '''    for prod in production_set:
        prod_base = os.path.basename(prod)
        for c in candidates:
            if os.path.basename(c) == prod_base and prod in production_set:
                return prod

    for c in candidates:
        if c in production_set:
            return c

    return None
'''
NEW = '''    exact = {c for c in candidates if c in production_set}
    if exact:
        return next(iter(exact)) if len(exact) == 1 else None

    basenames = {os.path.basename(c) for c in candidates}
    matches = {prod for prod in production_set if os.path.basename(prod) in basenames}
    return next(iter(matches)) if len(matches) == 1 else None
'''


def patched_bytes(original: bytes) -> bytes:
    if hashlib.sha256(original).hexdigest() != ORIGINAL_SHA256:
        raise ValueError('scanner source does not match the approved pin')
    source = original.decode('utf-8')
    if source.count(OLD) != 1:
        raise ValueError('scanner patch target is missing or ambiguous')
    return source.replace(OLD, NEW, 1).encode('utf-8')


def scanner_source() -> Path:
    spec = importlib.util.find_spec('desloppify.languages.typescript.test_coverage')
    if spec is None or spec.origin is None:
        raise ValueError('scanner module is unavailable')
    return Path(spec.origin)


def verify() -> None:
    if hashlib.sha256(scanner_source().read_bytes()).hexdigest() != PATCHED_SHA256:
        raise ValueError('approved scanner patch is missing or has changed')


def install() -> None:
    source = scanner_source()
    data = source.read_bytes()
    if hashlib.sha256(data).hexdigest() == PATCHED_SHA256:
        return
    replacement = patched_bytes(data)
    if hashlib.sha256(replacement).hexdigest() != PATCHED_SHA256:
        raise ValueError('scanner patch does not match its approved digest')
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=source.parent, prefix='.scanner-patch-', delete=False) as output:
            temporary = Path(output.name)
            os.fchmod(output.fileno(), source.stat().st_mode & 0o777)
            output.write(replacement)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, source)
        verify()
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


if __name__ == '__main__':
    install()
