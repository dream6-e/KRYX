#!/usr/bin/env bash
# KRYX 一键环境复原：干净机器/空沙箱上回到可构建、可测试状态。
# 用法：bash tools/setup-env.sh [--no-build]
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"
PREFIX=${OBF_RUST_PREFIX:-/usr/local/obf-rust-1.88.0}

echo '[1/5] 参考运行时权限（zip 会丢执行位）'
chmod +x toolchains/bin/* || true

echo '[2/5] Rust 1.88.0 工具链'
if [[ -x "$PREFIX/bin/rustc" ]] && "$PREFIX/bin/rustc" --version | grep -q '^rustc 1\.88\.0 '; then
    echo "      已就绪: $PREFIX"
else
    # crates.io / static.rust-lang.org 被墙时只能走 npm @rustbin 通道
    OBF_RUST_PREFIX="$PREFIX" bash tools/bootstrap-rust.sh
fi
export PATH="$PREFIX/bin:$PATH"

echo '[3/5] crates.io 可达性检测'
if curl -sS --max-time 8 -o /dev/null https://index.crates.io/config.json; then
    echo '      官方源可达，走常规 cargo 下载'
else
    echo '      官方源不可达（SSL_ERROR_SYSCALL），使用 GitHub 离线源'
    if [[ ! -f /usr/local/obf-crates-vendor/regex-1.12.4/Cargo.toml ]]; then
        python3 tools/offline-crates/vendor_crates.py
    else
        echo '      离线目录已存在，跳过 vendor'
    fi
    mkdir -p "$HOME/.cargo"
    if [[ ! -f "$HOME/.cargo/config.toml" ]]; then
        cat > "$HOME/.cargo/config.toml" <<'TOML'
[source.crates-io]
replace-with = "obf-vendored"

[source.obf-vendored]
directory = "/usr/local/obf-crates-vendor"

[net]
offline = true
TOML
        echo "      已写入 $HOME/.cargo/config.toml（删除该文件即回退）"
    elif ! grep -q 'obf-vendored' "$HOME/.cargo/config.toml"; then
        echo '!! $HOME/.cargo/config.toml 已存在且不含 obf-vendored，为避免破坏你的配置，请手动合并以下内容：'
        cat <<'TOML'
[source.crates-io]
replace-with = "obf-vendored"
[source.obf-vendored]
directory = "/usr/local/obf-crates-vendor"
[net]
offline = true
TOML
        exit 1
    fi
fi

if [[ "${1:-}" == "--no-build" ]]; then
    echo '[4/5] --no-build，跳过构建'
    echo '[5/5] 完成。记得: export PATH='"$PREFIX"'/bin:$PATH'
    exit 0
fi

echo '[4/5] cargo build'
cargo build

echo '[5/5] 完成。把这行加进你的 shell 配置：'
echo "  export PATH=$PREFIX/bin:\$PATH"
