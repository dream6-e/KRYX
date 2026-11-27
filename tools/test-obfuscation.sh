#!/usr/bin/env bash
#
# test-obfuscation.sh —— 混淆后运行 + 前后输出一致性检测
#
# 对每个 .lua 语料做三件事：① 跑源文件拿基准输出 ② 混淆 ③ 跑混淆产物并逐字节比对。
# 退出码：0 = 无失败；1 = 有失败（可直接接进 CI）。
#
# ──────────────────────────────────────────────────────────────────────────────
#  用法
# ──────────────────────────────────────────────────────────────────────────────
#
#   bash tools/test-obfuscation.sh [选项]
#
#   最常用（跑 test/ 下全部语料，跳过已知不可用的 Katchi 和慢速基准 hash）：
#
#       bash tools/test-obfuscation.sh
#
#   跑指定文件或目录：
#
#       bash tools/test-obfuscation.sh test/Prometheus
#       bash tools/test-obfuscation.sh test/print.lua examples/print.lua
#
#   每个文件重复 5 轮（用于捕捉「随机误编译」，见 环境部署.md §5.2）：
#
#       bash tools/test-obfuscation.sh --rounds 5
#
#   忽略计时差异（benchmark 类文件输出含 os.clock()，数值必然不同，见 §5.3）：
#
#       bash tools/test-obfuscation.sh --ignore-timing --rounds 3
#
#   测 MB 模式（额外把 MB 传给混淆器）：
#
#       bash tools/test-obfuscation.sh --mb
#
# ──────────────────────────────────────────────────────────────────────────────
#  选项
# ──────────────────────────────────────────────────────────────────────────────
#
#   --rounds N          每个文件重复 N 轮混淆+运行，默认 1
#   --ignore-timing     比对前把「小数形式的计时数值」统一替换，
#                       用于 benchmark*.lua / hash.lua 这类输出含计时的文件
#   --mb                以 MB 模式混淆（等价于 kryvex-simple <file> MB）
#   --exclude PATTERN   额外排除路径（可多次给），默认已排除 Katchi / hash
#   --no-default-exclude  不排除 Katchi / hash（想全测时用）
#   --timeout N         单次运行源文件/产物的超时秒数，默认 300
#   --keep              保留中间产物目录（默认跑完删除）
#   -h, --help          显示本帮助
#
# ──────────────────────────────────────────────────────────────────────────────
#  前置条件
# ──────────────────────────────────────────────────────────────────────────────
#
#   1. 已构建混淆器：
#          export PATH=/usr/local/obf-rust-1.88.0/bin:$PATH
#          cargo build
#      脚本会依次尝试 $OBF_BIN、target/debug/kryvex-simple、target/release/kryvex-simple。
#
#   2. 参考运行时存在：toolchains/bin/luau（仓库已入库；若丢了执行位先 chmod +x）。
#
#   3. 环境彻底丢了就跑 环境部署.md §0 的一键复原：
#          sudo bash tools/setup-env.sh --no-build
#
# ──────────────────────────────────────────────────────────────────────────────
#  判据与已知豁免
# ──────────────────────────────────────────────────────────────────────────────
#
#   · 唯一判据是「混淆产物运行输出 == 源文件运行输出」（逐字节）。
#   · 源文件自身就报错的语料会被标 SKIP，不算失败。
#   · 混淆器崩了、产物跑不起来、输出不一致 → FAIL。
#   · benchmark*.lua / hash.lua 的输出含 os.clock() 计时，数值必然不同；
#     加 --ignore-timing 后再比，能确认「除计时外完全一致」。
#   · test/Katchi.lua 因编译器 MAXSTACK=127 无法混淆（环境部署.md §5.1），
#     默认排除；想复现该问题用 --no-default-exclude。
#
# ──────────────────────────────────────────────────────────────────────────────
#  输出
# ──────────────────────────────────────────────────────────────────────────────
#
#   === test/Prometheus/loops.lua
#     PASS
#     ...
#   ======== 汇总: PASS=19 FAIL=0 SKIP=0 ========
#
#   失败时会打印产物报错的前几行或输出 diff 的前几行，便于直接定位。
#
set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT" || exit 1

# ── 默认参数 ──────────────────────────────────────────────────────────────────
ROUNDS=1
IGNORE_TIMING=0
MB_MODE=0
KEEP=0
RUN_TIMEOUT=300
DEFAULT_EXCLUDE=1
EXTRA_EXCLUDE=()
TARGETS=()

# ── 参数解析 ──────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --rounds|-r)      ROUNDS=${2:-1}; shift 2 ;;
        --ignore-timing)  IGNORE_TIMING=1; shift ;;
        --mb)             MB_MODE=1; shift ;;
        --exclude)        EXTRA_EXCLUDE+=("${2:-}"); shift 2 ;;
        --no-default-exclude) DEFAULT_EXCLUDE=0; shift ;;
        --timeout)        RUN_TIMEOUT=${2:-300}; shift 2 ;;
        --keep)           KEEP=1; shift ;;
        -h|--help)        sed -n '2,80p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*)               echo "未知选项: $1（用 --help 查看用法）" >&2; exit 2 ;;
        *)                TARGETS+=("$1"); shift ;;
    esac
done

[[ -n "${ROUNDS//[0-9]/}" ]] && { echo "--rounds 需要正整数" >&2; exit 2; }
[[ "$ROUNDS" -ge 1 ]] || { echo "--rounds 需要 >= 1" >&2; exit 2; }

# ── 定位工具 ──────────────────────────────────────────────────────────────────
find_obf() {
    if [[ -n "${OBF_BIN:-}" && -x "${OBF_BIN}" ]]; then echo "$OBF_BIN"; return; fi
    for c in target/debug/kryvex-simple target/release/kryvex-simple; do
        [[ -x "$c" ]] && { echo "$ROOT/$c"; return; }
    done
    return 1
}

OBF=$(find_obf) || {
    echo "错误: 找不到混淆器。先构建：" >&2
    echo "  export PATH=/usr/local/obf-rust-1.88.0/bin:\$PATH && cargo build" >&2
    exit 1
}

LUA="$ROOT/toolchains/bin/luau"
if [[ ! -x "$LUA" ]]; then
    echo "错误: 缺少参考运行时 $LUA" >&2
    echo "  修复: chmod +x toolchains/bin/*   （详见 环境部署.md §3）" >&2
    exit 1
fi

# ── 收集待测文件 ──────────────────────────────────────────────────────────────
if [[ ${#TARGETS[@]} -eq 0 ]]; then
    TARGETS=("test")
fi

collect() {
    local t
    for t in "${TARGETS[@]}"; do
        if [[ -d "$t" ]]; then
            find "$t" -type f -name '*.lua' -print
        elif [[ -f "$t" ]]; then
            printf '%s\n' "$t"
        else
            echo "跳过不存在的路径: $t" >&2
        fi
    done | sort
}

mapfile -t FILES < <(collect)
if [[ ${#FILES[@]} -eq 0 ]]; then
    echo "没有找到任何 .lua 文件" >&2
    exit 1
fi

# 默认排除：Katchi（无法混淆）、hash（基准类，跑得慢）
if [[ $DEFAULT_EXCLUDE -eq 1 ]]; then
    filtered=()
    for f in "${FILES[@]}"; do
        base=$(basename "$f")
        [[ "$base" == "Katchi.lua" ]] && continue
        [[ "$base" == "hash.lua" ]] && continue
        filtered+=("$f")
    done
    FILES=("${filtered[@]}")
fi

# 额外排除
for pat in ${EXTRA_EXCLUDE+"${EXTRA_EXCLUDE[@]}"}; do
    [[ -z "$pat" ]] && continue
    filtered=()
    for f in "${FILES[@]}"; do
        [[ "$f" == *"$pat"* ]] || filtered+=("$f")
    done
    FILES=("${filtered[@]}")
done

# ── 工作目录 ──────────────────────────────────────────────────────────────────
WORK=$(mktemp -d "${TMPDIR:-/tmp}/kryx-obftest.XXXXXX")
cleanup() {
    if [[ $KEEP -eq 1 ]]; then
        echo "[保留中间产物] $WORK"
    else
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT

# 每个文件独立子目录，避免产物互相覆盖
safe_name() { echo "$1" | sed 's|/|_|g; s| |_|g; s|(||g; s|)||g'; }

# ── 比对辅助 ──────────────────────────────────────────────────────────────────
# 抹掉小数形式的计时数值（如 0.002423 / 17.757517）
strip_timing() {
    sed -E 's/[0-9]+\.[0-9]+/<T>/g' "$1"
}

compare_outputs() {
    local a="$1" b="$2"
    if [[ $IGNORE_TIMING -eq 1 ]]; then
        diff -q <(strip_timing "$a") <(strip_timing "$b") >/dev/null 2>&1
    else
        cmp -s "$a" "$b"
    fi
}

# ── 主循环 ────────────────────────────────────────────────────────────────────
echo "混淆器 : $OBF"
echo "运行时 : $LUA"
echo "轮数   : $ROUNDS$([[ $MB_MODE -eq 1 ]] && echo '  (MB 模式)')$([[ $IGNORE_TIMING -eq 1 ]] && echo '  (忽略计时)')"
echo "文件数 : ${#FILES[@]}"
echo

PASS=0
FAIL=0
SKIP=0
declare -a FAIL_LIST=()

for f in "${FILES[@]}"; do
    echo "=== $f"
    safe=$(safe_name "$f")
    dir="$WORK/$safe"
    mkdir -p "$dir"

    # ① 源文件基准输出
    timeout "$RUN_TIMEOUT" "$LUA" "$f" >"$dir/src.out" 2>"$dir/src.err"
    src_rc=$?
    if [[ $src_rc -ne 0 ]]; then
        echo "  SKIP  源文件本身跑不通 (rc=$src_rc)"
        head -2 "$dir/src.err" 2>/dev/null | sed 's/^/         /'
        SKIP=$((SKIP + 1))
        continue
    fi

    fpass=0
    ffail=0
    last_reason=""

    for ((r = 1; r <= ROUNDS; r++)); do
        # ② 混淆：在独立目录内进行（混淆器固定输出 obfuscated.lua）
        cp "$f" "$dir/in.lua"
        rm -f "$dir/obfuscated.lua"
        gen_args=("in.lua")
        [[ $MB_MODE -eq 1 ]] && gen_args+=("MB")
        ( cd "$dir" && timeout 600 "$OBF" "${gen_args[@]}" >gen.log 2>&1 )
        gen_rc=$?

        if [[ $gen_rc -ne 0 || ! -f "$dir/obfuscated.lua" ]]; then
            ffail=$((ffail + 1))
            last_reason="混淆失败 (rc=$gen_rc)"
            continue
        fi

        # ③ 运行产物
        # 注意：不能用 `if ! cmd; then rc=$?` —— `!` 会把 $? 反转成 0，
        # 报出来的永远是 rc=0。必须先取 $? 再判断。
        timeout "$RUN_TIMEOUT" "$LUA" "$dir/obfuscated.lua" >"$dir/obf.out" 2>"$dir/obf.err"
        run_rc=$?
        if [[ $run_rc -ne 0 ]]; then
            ffail=$((ffail + 1))
            last_reason="运行失败 (rc=$run_rc)"
            continue
        fi

        # ④ 比对
        if compare_outputs "$dir/src.out" "$dir/obf.out"; then
            fpass=$((fpass + 1))
        else
            ffail=$((ffail + 1))
            last_reason="输出不一致"
        fi
    done

    if [[ $ffail -eq 0 ]]; then
        echo "  PASS  ($fpass/$ROUNDS)"
        PASS=$((PASS + 1))
    else
        echo "  FAIL  ($last_reason, $ffail/$ROUNDS 轮失败)"
        if [[ -s "$dir/obf.err" ]]; then
            head -2 "$dir/obf.err" | sed 's/^/         /'
        fi
        if [[ -f "$dir/src.out" && -f "$dir/obf.out" ]]; then
            diff "$dir/src.out" "$dir/obf.out" 2>/dev/null | head -6 | sed 's/^/         /'
        fi
        FAIL=$((FAIL + 1))
        FAIL_LIST+=("$f")
    fi
done

# ── 汇总 ──────────────────────────────────────────────────────────────────────
echo
if [[ $FAIL -gt 0 ]]; then
    echo "失败文件："
    printf '  - %s\n' "${FAIL_LIST[@]}"
    echo
fi
echo "======== 汇总: PASS=$PASS FAIL=$FAIL SKIP=$SKIP ========"

if [[ $FAIL -gt 0 ]]; then
    echo
    echo "排查提示："
    echo "  · 产物跑不起来 / 输出乱码 → 可能是随机误编译（环境部署.md §5.2），加 --rounds 5 复现"
    echo "  · benchmark*.lua 只在计时数值上不同 → 加 --ignore-timing 再跑"
    echo "  · 用例保留现场：加 --keep，脚本退出时会打印中间产物目录"
    exit 1
fi
exit 0
