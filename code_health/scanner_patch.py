"""Apply and verify reviewed corrections to the pinned scanner."""
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile

PATCH_ID = 'coverage-python-graph-nesting-dynamic-dicts-v5'
PATCHED_SHA256 = '7bab0ae5c1f31fe909a672a53483c26463e5115a730853c34bc9ecef4c0c8f24'
COMPONENTS = {'typescript': {'module': 'desloppify.languages.typescript.test_coverage',
                'original': 'ab59a286ef8165fb8c812d894c1e1db6a6facca547a4a32e96eb20a5cfb3cd1f',
                'patched': 'c3cc9f3d130093b6e9a289c67893e25fbcef44a3091bdd7bf081069dbee0d28f'},
 'python': {'module': 'desloppify.languages.python.test_coverage',
            'original': 'fc531fe162ab0ff0eabbc73f779d340bc9964aa1599964323cbfb7285d811986',
            'patched': 'a9109e1b617fcb53c2fae174b4bd8866e4df1a7e247077b789c13011f8ff1acc'},
 'python_graph': {'module': 'desloppify.languages.python.detectors.deps_resolution',
                  'original': '91381f7254ec7411068398f638349035337bbcd92d1f985c6d8f6c3fca00a1c4',
                  'patched': '36d7c99e42a62c7995316639027c663f8378201732b1f74cd76ca807629ab76e'},
 'python_complexity': {'module': 'desloppify.languages.python.detectors.complexity',
                       'original': '6abf6611927dd26d1af8fe1832e9bdbc4a0cf1537a7fa2740ade65f597cda861',
                       'patched': '78e5ce91d408515c627b5b09fe8105cf89140bff52a49ae80d0b9cedf2925d21'},
 'mapping': {'module': 'desloppify.engine.detectors.coverage.mapping_imports',
            'original': '625065243f813401187bb7c507753b328fe6f657c7f1faf995fcaafe224e015f',
            'patched': 'e89a7267a8e6e29072e8bc3b7655822a0efdcc8e9442921af2f87060c6b459fe'},
 'python_dict_shared': {'module': 'desloppify.languages.python.detectors.dict_keys.shared',
                        'original': '093008b9eee5c636fc807c02a61b497fd1171dc7f8a40dff2282b73e17e7a42b',
                        'patched': '194695793b52370825bd211a2a798dd27a5e3e4259f466efefeac96724a8e0b8'},
 'python_dict_visitor': {'module': 'desloppify.languages.python.detectors.dict_keys.visitor',
                         'original': '4e8dc299a7d75e66813c333c5929a84a0ab8cb2d83610dc528e4ce51237f7f8f',
                         'patched': 'b1ca8a0c0abee453fad47fa18ef7f139cec4889d1165fd7b6596d7ed5e0706f1'},
 'python_dict_helpers': {'module': 'desloppify.languages.python.detectors.dict_keys.visitor_helpers',
                         'original': '363ec1ee3311af9718d4120a098b9905cfb0cfcc215e4f1584ef3ff529799910',
                         'patched': 'f289d2a0aa893d30b998aa6b44e1bfefc908d654ccbf0edbfc53e6de64d3743a'}}
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
PY_RESOLVER = '''def resolve_import_spec(
    spec: str, test_path: str, production_files: set[str]
) -> str | None:
    """Resolve relative imports from the test's actual package directory."""
    if spec.startswith("."):
        if not test_path:
            return None
        level = len(spec) - len(spec.lstrip("."))
        directory = os.path.dirname(test_path)
        for _ in range(level - 1):
            parent = os.path.dirname(directory)
            if not parent or parent == directory:
                return None
            directory = parent
        name = spec[level:].replace(".", "/")
        target = os.path.normpath(os.path.join(directory, name))
        for candidate in (target + ".py", os.path.join(target, "__init__.py")):
            if candidate in production_files:
                return candidate
        return None
    module_path = spec.strip().replace(".", "/")
    if not module_path or module_path.startswith("/"):
        return None
    for candidate in (f"{module_path}.py", f"{module_path}/__init__.py"):
        if candidate in production_files:
            return candidate
        for prefix in _SRC_PREFIXES:
            prefixed = f"{prefix}{candidate}"
            if prefixed in production_files:
                return prefixed
        if test_path:
            sibling = os.path.join(os.path.dirname(test_path), candidate)
            if sibling in production_files:
                return sibling
    return None


'''
PY_PARSER = '''def parse_test_import_specs(content: str) -> list[str]:
    """Extract all syntactically valid imports, including aliases and groups."""
    tree = ast.parse(content)
    specs = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            specs.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            package = "." * node.level + (node.module or "")
            if package:
                specs.append(package)
            separator = "" if package.endswith(".") else "."
            specs.extend(package + separator + alias.name for alias in node.names if alias.name != "*")
    return specs


'''

PY_NESTING = '''def compute_nesting_depth(content: str, lines: list[str]) -> tuple[int, str] | None:
    """Count Python indentation blocks, excluding continuation alignment."""
    import io
    import tokenize

    depth = maximum = 0
    for token in tokenize.generate_tokens(io.StringIO(content).readline):
        if token.type == tokenize.INDENT:
            depth += 1
            maximum = max(maximum, depth)
        elif token.type == tokenize.DEDENT:
            depth -= 1
    if maximum > 4:
        return maximum, f"nesting depth {maximum}"
    return None


'''

def component_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def patched_component(component: str, original: bytes) -> bytes:
    spec = COMPONENTS[component]
    if component_digest(original) != spec['original']:
        raise ValueError('scanner source does not match the approved pin')
    source = original.decode('utf-8')
    if component == 'typescript':
        if source.count(OLD) != 1:
            raise ValueError('scanner patch target is missing or ambiguous')
        source = source.replace(OLD, NEW, 1)
    elif component == 'python':
        source = source.replace('import os\n', 'import ast\nimport os\n', 1)
        for name, following, replacement in [('resolve_import_spec', 'resolve_barrel_reexports', PY_RESOLVER),
                                               ('parse_test_import_specs', 'map_test_to_source', PY_PARSER)]:
            start = source.index('def ' + name + '(')
            end = source.index('def ' + following + '(', start)
            source = source[:start] + replacement + source[end:]
    elif component == 'python_graph':
        old = '    if target and import_names:\n'
        if source.count(old) != 1:
            raise ValueError('scanner graph patch target is missing or ambiguous')
        source = source.replace(old, '    if import_names:\n', 1)
    elif component == 'python_complexity':
        start = source.index('def compute_nesting_depth(')
        end = source.index('def compute_long_functions(', start)
        source = source[:start] + PY_NESTING + source[end:]
    elif component == 'mapping':
        old = '        # Fallback: module-name lookup with progressively shorter prefixes.\n'
        new = '        if lang_name == "python" and spec.startswith("."):\n            continue\n' + old
        if source.count(old) != 1:
            raise ValueError('scanner mapping patch target is missing or ambiguous')
        source = source.replace(old, new, 1)
    elif component == 'python_dict_shared':
        source = source.replace('    has_dynamic_key: bool = False\n',
                                '    has_dynamic_key: bool = False\n    has_dynamic_write: bool = False\n', 1)
    elif component == 'python_dict_visitor':
        old = '        if key:\n            td.writes[key].append(line)\n        else:\n            td.has_dynamic_key = True\n'
        if source.count(old) != 1:
            raise ValueError('scanner dynamic-dictionary patch target is missing or ambiguous')
        source = source.replace(old, old + '            td.has_dynamic_write = True\n', 1)
    elif component == 'python_dict_helpers':
        old = '                        else:\n                            tracked.has_dynamic_key = True\n                elif method == "update":\n'
        new = '                        else:\n                            tracked.has_dynamic_key = True\n                            tracked.has_dynamic_write = True\n                elif method == "update":\n'
        if source.count(old) != 1:
            raise ValueError('scanner dynamic-dictionary patch target is missing or ambiguous')
        source = source.replace(old, new, 1)
        old = '                            elif key_node is None:\n                                tracked.has_dynamic_key = True\n'
        new = old + '                                tracked.has_dynamic_write = True\n'
        if source.count(old) != 1:
            raise ValueError('scanner dynamic-dictionary patch target is missing or ambiguous')
        source = source.replace(old, new, 1)
        old = '                    for kw in node.keywords:\n'
        new = '                    elif node.args:\n                        tracked.has_dynamic_key = True\n                        tracked.has_dynamic_write = True\n                    for kw in node.keywords:\n'
        if source.count(old) != 1:
            raise ValueError('scanner dynamic-dictionary patch target is missing or ambiguous')
        source = source.replace(old, new, 1)
        old = '                        else:\n                            tracked.has_dynamic_key = True\n                elif method in _BULK_READ_METHODS:\n'
        new = '                        else:\n                            tracked.has_dynamic_key = True\n                            tracked.has_dynamic_write = True\n                elif method in _BULK_READ_METHODS:\n'
        if source.count(old) != 1:
            raise ValueError('scanner dynamic-dictionary patch target is missing or ambiguous')
        source = source.replace(old, new, 1)
        source = source.replace('        phantom_keys = read_keys - written_keys\n',
                                '        phantom_keys = read_keys - written_keys if not tracked.has_dynamic_write else set()\n', 1)
    else:
        raise ValueError('unknown scanner component')
    data = source.encode('utf-8')
    if component_digest(data) != spec['patched']:
        raise ValueError('scanner patch does not match its approved digest')
    return data


def scanner_source(component: str = 'typescript') -> Path:
    spec = importlib.util.find_spec(COMPONENTS[component]['module'])
    if spec is None or spec.origin is None:
        raise ValueError('scanner module is unavailable')
    return Path(spec.origin)


def verify() -> None:
    observed = {name: component_digest(scanner_source(name).read_bytes()) for name in COMPONENTS}
    if any(observed[name] != COMPONENTS[name]['patched'] for name in COMPONENTS):
        raise ValueError('approved scanner patch is missing or has changed')
    identity = ''.join(f'{name}:{observed[name]}\n' for name in sorted(observed)).encode()
    if component_digest(identity) != PATCHED_SHA256:
        raise ValueError('scanner patch identity differs from its approved digest')


def install() -> None:
    pending = []
    for name, spec in COMPONENTS.items():
        source = scanner_source(name)
        data = source.read_bytes()
        if component_digest(data) == spec['patched']:
            continue
        pending.append((source, patched_component(name, data)))
    staged = []
    try:
        for source, replacement in pending:
            with tempfile.NamedTemporaryFile(dir=source.parent, prefix='.scanner-patch-', delete=False) as output:
                temporary = Path(output.name)
                staged.append(temporary)
                os.fchmod(output.fileno(), source.stat().st_mode & 0o777)
                output.write(replacement)
                output.flush()
                os.fsync(output.fileno())
        for (source, _), temporary in zip(pending, staged):
            os.replace(temporary, source)
        verify()
    finally:
        for temporary in staged:
            temporary.unlink(missing_ok=True)


if __name__ == '__main__':
    install()
