#!/usr/bin/env python3
"""Vendor EVERY registry package in Cargo.lock into a cargo directory source.

Explicit (name, version, repo, ref) specs; ref may be a tag or commit.
Sources: official tags where they exist, GitHub-maintained mirrors of the
crates.io artifacts (single-crate AOSP-style mirrors / packaging repos) for
the yanked/deleted ones (errno 0.3.14 has no tag upstream anywhere we can see;
crossterm_winapi 0.9.1's upstream repo stops at 0.6.1).
"""
import os, re, subprocess, sys, tarfile, shutil, json, urllib.request
import tomllib

def _install_tomlkit():
    for extra in ([], ['--break-system-packages'], ['--user']):
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--quiet', 'tomlkit', *extra])
            return
        except subprocess.CalledProcessError:
            continue
    raise RuntimeError('could not install tomlkit (tried plain, --break-system-packages, --user)')

try:
    import tomlkit
except ModuleNotFoundError:
    _install_tomlkit()
    import tomlkit

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VENDOR = os.environ.get('OBF_crates_vendor', '/usr/local/obf-crates-vendor')
CACHE = os.environ.get('OBF_crates_cache', '/tmp/offline-crates/cache')
os.makedirs(CACHE, exist_ok=True)
os.makedirs(VENDOR, exist_ok=True)

lock = open(f'{REPO}/Cargo.lock').read()
pgs = {}
for m in re.finditer(r'\[\[package\]\]\n(.*?)(?=\n\[\[package\]\]|\Z)', lock, re.S):
    p = m.group(1)
    name = re.search(r'name = "([^"]+)"', p).group(1)
    ver = re.search(r'version = "([^"]+)"', p).group(1)
    chk = re.search(r'checksum = "([^"]+)"', p)
    src = re.search(r'source = "([^"]+)"', p)
    if src:
        pgs[(name, ver)] = chk.group(1) if chk else None

# (name, version, repo, ref) — ref None means "<version>" tag
S = [
    ('aho-corasick',  '1.1.4',   'BurntSushi/aho-corasick', None),
    ('bitflags',      '2.13.0',  'bitflags/bitflags', None),
    ('cfg-if',        '1.0.4',   'rust-lang/cfg-if', None),
    ('crossterm',     '0.27.0',  'crossterm-rs/crossterm', None),
    ('crossterm_winapi','0.9.1', 'ruancomelli/crossterm-winapi-0.9.1', 'v0.9.1'),
    ('errno',         '0.3.14',  'lambda-fairy/rust-errno', 'ffc03bfb9eb491013567115e6eea560948cd9e52'),
    ('getrandom',     '0.3.4',   'rust-random/getrandom', None),
    ('libc',          '0.2.186', 'rust-lang/libc', None),
    ('lock_api',      '0.4.14',  'Amanieu/parking_lot', 'lock_api-v0.4.14'),
    ('log',           '0.4.33',  'rust-lang/log', None),
    ('memchr',        '2.8.2',   'BurntSushi/memchr', None),
    ('mio',           '0.8.11',  'tokio-rs/mio', None),
    ('parking_lot',   '0.12.5',  'Amanieu/parking_lot', 'parking_lot-v0.12.5'),
    ('parking_lot_core','0.9.12','Amanieu/parking_lot', 'parking_lot_core-v0.9.12'),
    ('ppv-lite86',    '0.2.21',  'cryptocorrosion/cryptocorrosion', 'ppv-lite86-0.2.21'),
    ('proc-macro2',   '1.0.106', 'dtolnay/proc-macro2', None),
    ('quote',         '1.0.45',  'dtolnay/quote', None),
    ('r-efi',         '5.3.0',   'r-efi/r-efi', None),
    ('rand',          '0.9.4',   'rust-random/rand', '0.9.4'),
    ('rand_chacha',   '0.9.0',   'rust-random/rand', '0.9.4'),
    ('rand_core',     '0.9.5',   'rust-random/rand_core', 'a34dab266970'),
    ('redox_syscall', '0.5.18',  'redox-os/syscall', None),
    ('regex',         '1.12.4',  'rust-lang/regex', '1.12.4'),
    ('regex-automata','0.4.14',  'rust-lang/regex', '1.12.4'),
    ('regex-syntax',  '0.8.11',  'rust-lang/regex', '1.12.4'),
    ('scopeguard',    '1.2.0',   'bluss/scopeguard', None),
    ('signal-hook',   '0.3.18',  'vorner/signal-hook', None),
    ('signal-hook-mio','0.2.5',  'vorner/signal-hook', 'mio-v0.2.5'),
    ('signal-hook-registry','1.4.8','vorner/signal-hook', 'registry-v1.4.8'),
    ('smallvec',      '1.15.2',  'servo/rust-smallvec', None),
    ('syn',           '2.0.117', 'dtolnay/syn', None),
    ('unicode-ident', '1.0.24',  'dtolnay/unicode-ident', None),
    ('wasi',          '0.11.1+wasi-snapshot-preview1', 'bytecodealliance/wasi-rs', '0.11.1'),
    ('wasip2',        '1.0.4+wasi-0.2.12', 'bytecodealliance/wasi-rs', 'wasip2-1.0.4'),
    ('wit-bindgen',   '0.57.1',  'bytecodealliance/wit-bindgen', None),
    ('windows-sys',   '0.48.0',  'microsoft/windows-rs', '0.48.0'),
    ('windows-sys',   '0.61.2',  'microsoft/windows-rs', '71'),
    ('windows-targets','0.48.5', 'microsoft/windows-rs', '0.48.5'),
    ('windows-link',  '0.2.1',   'microsoft/windows-rs', '71'),
    ('windows_aarch64_gnullvm','0.48.5','microsoft/windows-rs', '0.48.5'),
    ('windows_aarch64_msvc','0.48.5',  'microsoft/windows-rs', '0.48.5'),
    ('windows_i686_gnu','0.48.5',      'microsoft/windows-rs', '0.48.5'),
    ('windows_i686_msvc','0.48.5',     'microsoft/windows-rs', '0.48.5'),
    ('windows_x86_64_gnu','0.48.5',    'microsoft/windows-rs', '0.48.5'),
    ('windows_x86_64_gnullvm','0.48.5','microsoft/windows-rs', '0.48.5'),
    ('windows_x86_64_msvc','0.48.5',   'microsoft/windows-rs', '0.48.5'),
    ('winapi',        '0.3.9',   'retep998/winapi-rs', None),
    ('winapi-i686-pc-windows-gnu','0.4.0','retep998/winapi-rs', '0.3.9'),
    ('winapi-x86_64-pc-windows-gnu','0.4.0','retep998/winapi-rs', '0.3.9'),
    ('zerocopy',      '0.8.52',  'google/zerocopy', None),
    ('zerocopy-derive','0.8.52', 'google/zerocopy', None),
]

assert {(n, v) for n, v, _, _ in S} == set(pgs), \
    f"spec/lock mismatch: {set(pgs) ^ {(n,v) for n,v,_,_ in S}}"

def resolve_ref(repo, version):
    out = subprocess.run(['git', 'ls-remote', '--tags', f'https://github.com/{repo}'],
                         capture_output=True, text=True, check=True).stdout
    tags = [r for r in re.findall(r'refs/tags/(\S+?)(\^\{\})?\s*$', out, re.M)]
    plain = [t[0] for t in tags]
    for cand in (version, f'v{version}'):
        if cand in plain:
            return cand
    hits = [t for t in plain if t.endswith('/' + version) or t.endswith('-' + version)]
    if len(hits) == 1:
        return hits[0]
    raise RuntimeError(f'cannot resolve tag for {version} in {repo}: {hits}')

def tarball(repo, ref):
    url = f'https://codeload.github.com/{repo}/tar.gz/{ref}'
    dst = f'{CACHE}/{repo.replace("/", "_")}__{ref.replace("/", "_")}.tar.gz'
    if not os.path.exists(dst):
        print('download', url, flush=True)
        urllib.request.urlretrieve(url, dst)
    return dst

def extract(tgz):
    dest = tgz[:-7] + '.x'
    if os.path.isdir(dest):
        shutil.rmtree(dest)
    os.makedirs(dest, exist_ok=True)
    with tarfile.open(tgz) as tf:
        tf.extractall(dest)
    return os.path.join(dest, os.listdir(dest)[0])

def find_ws_root(crate_dir):
    d = crate_dir
    while True:
        ct = os.path.join(d, 'Cargo.toml')
        if os.path.exists(ct):
            with open(ct, 'rb') as f:
                data = tomllib.load(f)
            if 'workspace' in data:
                return data, d
        parent = os.path.dirname(d)
        if parent == d:
            return None, None
        d = parent

def inline_inheritance(crate_dir):
    mpath = os.path.join(crate_dir, 'Cargo.toml')
    ws_data, _ = find_ws_root(crate_dir)
    if ws_data is None:
        return
    ws = ws_data.get('workspace', {})
    ws_pkg, ws_deps, ws_lints = ws.get('package', {}), ws.get('dependencies', {}), ws.get('lints', {})
    with open(mpath) as f:
        doc = tomlkit.parse(f.read())
    if 'package' in doc:
        pkg = doc['package']
        for key in list(pkg.keys()):
            val = pkg[key]
            if isinstance(val, dict) and val.get('workspace') is True:
                if key in ws_pkg:
                    pkg[key] = ws_pkg[key]
                else:
                    del pkg[key]
    for section in ('dependencies', 'dev-dependencies', 'build-dependencies'):
        if section not in doc:
            continue
        sec = doc[section]
        for dep in list(sec.keys()):
            spec = sec[dep]
            if not isinstance(spec, dict) or spec.get('workspace') is not True:
                continue
            root = ws_deps.get(dep)
            if root is None:
                raise RuntimeError(f'workspace dep {dep} not in {mpath}')
            merged = dict(root) if isinstance(root, dict) else {'version': root}
            child = {k: v for k, v in spec.items() if k != 'workspace'}
            feats = list(dict.fromkeys(list(merged.get('features', [])) + list(child.pop('features', []))))
            merged.update(child)
            if feats:
                merged['features'] = feats
            sec[dep] = tomlkit.item(merged)
    if isinstance(doc.get('lints'), dict) and doc['lints'].get('workspace') is True:
        if ws_lints:
            doc['lints'] = tomlkit.item(ws_lints)
        else:
            del doc['lints']
    with open(mpath, 'w') as f:
        f.write(tomlkit.dumps(doc))

roots = {}
for name, ver, repo, ref in S:
    if repo is None:
        continue
    ref = ref or resolve_ref(repo, ver)
    key = (repo, ref)
    if key not in roots:
        roots[key] = extract(tarball(repo, ref))
    root = roots[key]
    hits = []
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d != 'target' and d != '.git']
        if 'Cargo.toml' in files:
            with open(os.path.join(dirpath, 'Cargo.toml'), 'rb') as f:
                try:
                    data = tomllib.load(f)
                except Exception:
                    continue
            pkg = data.get('package') or {}
            n, v = pkg.get('name'), pkg.get('version')
            if isinstance(v, dict):
                tgd, _ = find_ws_root(dirpath)
                v = (tgd or {}).get('workspace', {}).get('package', {}).get('version')
            if n == name and v == ver:
                hits.append(dirpath)
    if len(hits) != 1:
        raise RuntimeError(f'{name} {ver}: hits={hits}')
    crate_dir = hits[0]
    inline_inheritance(crate_dir)
    dest = f'{VENDOR}/{name}-{ver}'
    if os.path.isdir(dest):
        shutil.rmtree(dest)
    shutil.copytree(crate_dir, dest)
    with open(f'{dest}/.cargo-checksum.json', 'w') as f:
        json.dump({'files': {}, 'package': pgs[(name, ver)]}, f)
    print(f'vendored {name}-{ver}', flush=True)

print('DONE')
