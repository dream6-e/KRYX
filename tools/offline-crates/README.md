# offline-crates — crates.io 被墙时的离线源

`vendor_crates.py` 按 `Cargo.lock` 的 51 个注册表包，**从 GitHub 取源码**拼出 cargo 的 directory 源（`/usr/local/obf-crates-vendor`），再由 `~/.cargo/config.toml`
做 source replacement + `offline = true`。由 `tools/setup-env.sh` 自动调用。

```bash
python3 tools/offline-crates/vendor_crates.py
```

仓库里不放任何 crate 源码；脚本每次运行从 GitHub 现拉。

## 来源与可信度（重要）

crates.io 全系不可达（SSL_ERROR_SYSCALL），因此**无法向注册表核对 package 校验和**；
directory 源里每个 `.cargo-checksum.json` 的 `package` 字段填的是 Cargo.lock 的校验和，
cargo 只据此与 lock 比对，不重新哈希——构建通过 ≠ 与 crates.io 产物逐字节一致。
信任链建立在"GitHub 上对应仓库/tag 的源码"上。来源构成：

- 官方仓库 tag（大多数）：如 rand / regex / libc / memchr / syn…
- **未打 tag 的发布提交**：`errno 0.3.14` → `lambda-fairy/rust-errno@ffc03bfb9eb491013567115e6eea560948cd9e52`（"Release 0.3.14. (#118)"，2025-09-08；上游只有 tag v0.3.13 和 v0.3.15，0.3.14 未打 tag）
- **第三方单 crate 镜像**（上游仓库已删除或止步于旧版）：`crossterm_winapi 0.9.1` → `ruancomelli/crossterm-winapi-0.9.1`（含 `.cargo_vcs_info.json`，为 crates.io 产物快照；上游 `crossterm-rs/crossterm-winapi` 最高 tag 仅 0.6.1）
- **monorepo tag**：`ppv-lite86 0.2.21` → `cryptocorrosion/cryptocorrosion` tag `ppv-lite86-0.2.21`（`jedisct1/ppv-lite86` 已 404）
- 按文档固定：`rand_core 0.9.5` → `rust-random/rand_core@backports/v0.9` 的 `a34dab266970`（无 release tag）
- **windows-rs 仓库**：tag `0.48.0`（windows-sys 0.48.0）、tag `0.48.5`（windows-targets 及 7 个 arch crate）、tag `71`（windows-sys 0.61.2 + windows-link 0.2.1）
- winapi 架构包：`retep998/winapi-rs` tag `0.3.9`  tarball 内自带 `i686/` `x86_64/` 子 crate（0.4.0）
- `wasi 0.11.1` / `wasip2 1.0.4`：`bytecodealliance/wasi-rs` tag `0.11.1` / `wasip2-1.0.4`

其余包均来自其官方仓库的对应版本 tag。脚本带自检：`S` 列表必须与 lock 的注册表包集合完全一致，否则直接报错退出。

## 环境变量

- `OBF_crates_vendor`（默认 `/usr/local/obf-crates-vendor`）：directory 源输出目录
- `OBF_crates_cache`（默认 `/tmp/offline-crates/cache`）：tarball 缓存

## 不需要 stub_crates

当前 lock 没有 Windows 占位包需求（winapi 系全部取到真源码），因此没有占位包逻辑。
若未来 lock 引入取不到源码的平台专用包，需另行处理并在此说明。
