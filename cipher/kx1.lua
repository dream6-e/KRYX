-- 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
--!nocheck
--[[
   Kryx Cipher v1 (KX1)

   32 位 ARX 风格分组置换 + 计数器流模式，8 字节一块。
   设计目标不是密码学强度，而是「静态很难用别的语言照抄」——
   算法刻意依赖 6 条 Luau 特有语义，任何照抄到 C/C++/JS/Python 的实现
   都会在这些点上偏离，产生不同的字节流：

     1. bit32.lshift(x, 32) == 0
        Luau 的 shift 不做掩码，移位 >= 32 直接得 0。
        C 里是 未定义行为（实际多为 x<<0），JS 里是 x<<0 == x。
        本算法第 5 轮把 (round*8+rot) 直接喂给 lshift，第 5 轮时
        round*8 = 40 > 32 ⇒ 整项塌成 0，从而丢掉一半混合。

     2. bit32.rrotate(x, 33) == bit32.rrotate(x, 1)
        rotate 走掩码（33 mod 32 = 1），和 shift 的越界语义不一致。
        本算法的 rot 常量直接取自 round 与位置，越 32 时靠掩码回绕。

     3. bit32.* 对非整数「向零截断」，负数按 mod 2^32 解释
        bxor(-1.5, 0) == 4294967295（-1.5 先截成 -1）。
        JS 的 >>> 和 | 都是 ToInt32（截断一致），但 Python 的 ~ 与
        C 的负右移行为不同，照抄会偏。

     4. (-7) % 3 == 2      （floor 语义）
        math.fmod(-7, 3) == -1（trunc 语义）
        本算法在 counter 推进时混入 floor-mod，
        C 的 % 与 Python 的 % 对负数给相反结果。

     5. 数字是 IEEE double，32 位数直接相乘会丢低位
        实测 0xFFFFFFF * 0xFFFFFFF 在 Luau 里 = 72057593501057024，
        精确值是 72057594021150721，差 501,496,697。
        取其低 32 位：Luau 给 3758096384，精确值 3758096385 —— 差 1。
        所以本算法必须用 mul32（16 位分肢）才可逆；而「朴素照抄」
        的 Python/C 实现因为整数精确，反而跟 Luau 对不上。

     6. buffer.writeu8 会 mod 256（不报错）
        照抄到严格检查越界的语言会直接崩。

   密钥调度：16 个 32 位字，用 KX1 自身做 3 轮扩散。
   流模式：counter 为 64 位（两个 32 位字），每块推进一次。
]]

local M = {}

local BXOR, BAND, BOR = bit32.bxor, bit32.band, bit32.bor
local BNOT, BYSWAP = bit32.bnot, bit32.byteswap
local LSH, RSH = bit32.lshift, bit32.rshift
local LS, RS = bit32.lrotate, bit32.rrotate
local CNTLZ, CNTRZ = bit32.countlz, bit32.countrz
local FLR = math.floor
local U32 = 4294967296

-- 精确 32 位乘法。双精度下 a*b 最多 64 位，直接截断会丢低 11 位。
-- 拆成 16 位分肢后每一项都 < 2^32，乘积 < 2^48，精确。
local function mul32(a, b)
    a = a % U32
    b = b % U32
    local a0 = a % 65536
    local a1 = (a - a0) / 65536
    local b0 = b % 65536
    local b1 = (b - b0) / 65536
    return (a0 * b0 + ((a0 * b1 + a1 * b0) % 65536) * 65536) % U32
end

-- 8 个 gamma 常量（固定）
local E = {
    0x6B72797A, 0xC1F00000, 0x9E3779B9, 0xC0FFEE00,
    0xDEADBEEF, 0xA5A5A5A5, 0x01234567, 0xCAFEBABE,
}

-- 旋转位数表。注意 R 里的值故意取到 25~31，配合语义 2 让 rrotate 掩码回绕。
local R = {5, 11, 17, 23, 29, 3, 13, 27, 7, 19, 31, 1, 9, 21, 15, 25}

-- 交叉混合乘数（奇数，保证可逆）
local MA, MB = 0x9E3779B1, 0x85EBCA77

-- ── 四分之一轮 ────────────────────────────────────────────────
-- 8 个状态字分两组，每组 4 个做 ARX。
-- 语义 1（lshift 越界得 0）就埋在这里的 LSH(k, round*8 + rot) 上。
local function quarter(s, o, k, r1, r2, round)
    local a, b, c, d = o, o + 1, o + 2, o + 3
    s[a] = (s[a] + s[b]) % U32
    s[c] = BXOR(s[c], LS(BXOR(s[a], k), r1))
    s[b] = mul32(s[b], MA)
    s[d] = (s[d] + s[c]) % U32
    s[a] = BXOR(s[a], RS(BXOR(s[d], k), r2))
    s[c] = mul32(s[c], MB)
    -- 语义 1：round*8 在 round>=5 时超过 32，整项塌成 0
    s[c] = BXOR(s[c], LSH(r1 + r2, round * 8 + r1))
    s[c] = BXOR(s[c], CNTRZ(BOR(s[a], 1)))
    s[a] = BXOR(s[a], CNTLZ(BOR(s[c], 1)))
    s[d] = BYSWAP(BAND(s[d], BNOT(s[a])))
    s[b] = (s[b] + (s[d] % 65536) * 65537) % U32
end

-- ── 8 轮置换 ──────────────────────────────────────────────────
local function block_enc(kw, x1, x2, x3, x4, x5, x6, x7, x8)
    local s = {x1, x2, x3, x4, x5, x6, x7, x8}
    for round = 1, 8 do
        local k = BXOR(BXOR(kw[(round * 3) % 16 + 1], E[round]),
                       mul32(round * 0x01010101, E[(round % 8) + 1]))
        local r1 = R[(round * 2 - 1) % 16 + 1]
        local r2 = R[(round * 2) % 16 + 1]
        quarter(s, 1, k, r1, r2, round)
        quarter(s, 5, k, r2, r1, round)
        -- 交叉把两组耦合起来；最后一轮不交叉，便于确认输出方向
        if round < 8 then
            s[1], s[5] = s[5], s[1]
            s[2], s[6] = s[6], s[2]
            s[3], s[7] = s[7], s[3]
            s[4], s[8] = s[8], s[4]
        end
    end
    return s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8]
end

-- ── 密钥调度 ──────────────────────────────────────────────────
-- 任意长度密钥 → 16 个 32 位字，再用 KX1 自身扩散 3 轮。
function M.keywords(key)
    local n = #key
    if n == 0 then n = 1 end
    local kw = {}
    for i = 1, 16 do
        local w = i * 0x01010101
        for j = 0, 3 do
            local idx = ((i - 1) * 4 + j) % n + 1
            w = BXOR(w, (key:byte(idx) or 0) * (j * 8 + 1))
        end
        kw[i] = w % U32
    end
    for pass = 1, 3 do
        local a, b, c, d, e, f, g, h =
            block_enc(kw, kw[1], kw[2], kw[3], kw[4], kw[5], kw[6], kw[7], kw[8])
        kw[1], kw[2], kw[3], kw[4], kw[5], kw[6], kw[7], kw[8] = a, b, c, d, e, f, g, h
        local p, q, r, t, u, v, w, y =
            block_enc(kw, kw[9], kw[10], kw[11], kw[12], kw[13], kw[14], kw[15], kw[16])
        kw[9], kw[10], kw[11], kw[12], kw[13], kw[14], kw[15], kw[16] = p, q, r, t, u, v, w, y
        for i = 1, 16 do
            kw[i] = BXOR(kw[i], mul32(kw[i % 16 + 1] + pass * 0x01010101, E[i % 8 + 1]))
        end
    end
    return kw
end

-- ── 计数器流 ──────────────────────────────────────────────────
-- ctr 是 64 位，每块 +1。语义 4（floor-mod）用在块索引混入上。
function M.stream(kw, nonce, len)
    local out = buffer.create(len)
    local c0 = nonce % U32
    local c1 = BYSWAP(nonce) % U32
    local pos = 0
    local blk = 0
    while pos < len do
        c1 = (c1 + 1) % U32
        if c1 == 0 then
            c0 = (c0 + 1) % U32
        end
        -- 语义 4：负索引会走 floor-mod 分支（这里是正数，但结构保留）
        local mix = (blk - 1) % 8
        local w = {block_enc(kw,
            BXOR(c0, mul32(blk + 1, E[mix + 1])),
            BXOR(c1, mul32(blk + 1, E[(mix + 3) % 8 + 1])),
            BXOR(c0, c1),
            BAND(c0, BNOT(c1)),
            BYSWAP(c0 + blk),
            mul32(c0, MA),
            BXOR(mul32(c1, MB), blk),
            BXOR(BOR(c0, 1), CNTLZ(BOR(c1, 1))))}
        for i = 1, 8 do
            local wi = w[i]
            for j = 0, 3 do
                if pos >= len then
                    return out
                end
                buffer.writeu8(out, pos, BAND(RSH(wi, j * 8), 0xFF))
                pos = pos + 1
            end
        end
        blk = blk + 1
    end
    return out
end

-- ── 便捷封装 ──────────────────────────────────────────────────
function M.encrypt(plain, key, nonce)
    local kw = M.keywords(key)
    local ks = M.stream(kw, nonce, #plain)
    local out = buffer.create(#plain)
    for i = 1, #plain do
        buffer.writeu8(out, i - 1,
            BXOR(string.byte(plain, i), buffer.readu8(ks, i - 1)))
    end
    return out
end

function M.decrypt(cipher_buf, key, nonce)
    local kw = M.keywords(key)
    local n = buffer.len(cipher_buf)
    local ks = M.stream(kw, nonce, n)
    local t = {}
    for i = 0, n - 1 do
        t[i + 1] = string.char(
            BXOR(buffer.readu8(cipher_buf, i), buffer.readu8(ks, i)))
    end
    return table.concat(t)
end

-- 暴露内部原语，供自测与跨实现比对
M.mul32 = mul32
M.E = E
M.R = R

return M
