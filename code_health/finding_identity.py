"""Recognise uniquely unchanged Python scopes for relocated security findings."""
import ast
from functools import lru_cache
import hashlib
import os
import stat
from pathlib import Path, PurePosixPath

MAX_SOURCE_BYTES = 1024 * 1024


class FindingIdentity:
    def __init__(self, base: Path, head: Path):
        self.roots = {'base': base.resolve(), 'head': head.resolve()}

    @lru_cache(maxsize=32)
    def _source(self, side: str, name: str):
        path = PurePosixPath(name)
        if not name or path.is_absolute() or '..' in path.parts or '\\' in name or path.as_posix() != name:
            return None
        root = self.roots[side]
        fd = None
        try:
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            for part in path.parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            child = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            os.close(fd)
            fd = child
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_SOURCE_BYTES:
                return None
            with os.fdopen(fd, 'rb') as source_file:
                fd = None
                data = source_file.read(MAX_SOURCE_BYTES + 1)
            if len(data) > MAX_SOURCE_BYTES:
                return None
            source = data.decode('utf-8')
            tree = ast.parse(source)
        except (OSError, UnicodeError, SyntaxError, ValueError, RecursionError, RuntimeError):
            return None
        finally:
            if fd is not None:
                os.close(fd)
        return source, tree

    def fingerprint(self, finding: dict, renames: dict, side: str):
        path = finding['file']
        identity = tuple(renames.get(part, part) for part in finding['id'].split('::'))
        fallback = (finding['detector'], renames.get(path, path), identity)
        detail = finding.get('detail')
        if (finding['detector'] != 'security' or not path.endswith('.py') or not isinstance(detail, dict)
                or detail.get('source') not in {None, 'bandit'}):
            return fallback
        uncertain = (finding['detector'], renames.get(path, path), ('unverified-source', side, *identity))
        if (type(detail.get('line')) is not int or detail['line'] < 1
                or not isinstance(detail.get('kind'), str)
                or (detail.get('source') == 'bandit' and not isinstance(detail.get('test_name'), str))
                or not identity or identity[-1] != str(detail['line'])):
            return uncertain
        parsed = self._source(side, path)
        if parsed is None:
            return uncertain
        source, tree = parsed
        line = detail['line']
        scopes = [node for node in ast.walk(tree)
                  if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                  and node.lineno <= line <= node.end_lineno]
        if not scopes or any(node.decorator_list for node in scopes):
            return uncertain
        scopes.sort(key=lambda node: (node.lineno, -node.end_lineno))
        evidence = []
        for node in scopes:
            text = ast.get_source_segment(source, node)
            if not text or source.count(text) != 1:
                return uncertain
            evidence.append((hashlib.sha256(text.encode()).hexdigest(), line - node.lineno))
        return (finding['detector'], renames.get(path, path),
                ('unique-unchanged-python-scope', *identity[:-1], detail['kind'], detail.get('test_name'),
                 finding.get('summary'), finding.get('tier'), finding.get('confidence'), tuple(evidence)))
