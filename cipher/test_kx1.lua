-- 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
--!nocheck
--[[  KX1 自测。用法：把 kx1.lua 与本文件拼成一个文件跑（本 luau 无 io/dofile）。 ]]

local pass, fail = 0, 0
local function chk(name, cond, extra)
    if cond then pass = pass + 1
    else fail = fail + 1; print("  FAIL " .. name .. (extra and ("  " .. tostring(extra)) or "")) end
end

local function same_buf(a, b, n)
    for i = 0, n - 1 do
        if buffer.readu8(a, i) ~= buffer.readu8(b, i) then return false, i end
    end
    return true
end

local function bitdiff(a, b, n)
    local d = 0
    for i = 0, n - 1 do
        local z = bit32.bxor(buffer.readu8(a, i), buffer.readu8(b, i))
        while z > 0 do d = d + (z % 2); z = math.floor(z / 2) end
    end
    return d
end

print("== 1. mul32 与精确值一致 ==")
-- 这几组在朴素 a*b % 2^32 下会差 1，见 kx1.lua 注释语义 5
for _, c in ipairs({
    {0xFFFFFFF, 0xFFFFFFF, 3758096385},
    {0xFFFFFFF, 0x3FFFFFF, 3959422977},
    {0x5DEECE6, 0xFFFFFFF, 1512117018},
    {0x7FFFFFF, 0xFEDCBA9, 940717143},
    {0xFFFFFFFF, 0xFFFFFFFF, 1},
    {0x12345678, 0x9ABCDEF0, 0x242D2080},
}) do
    chk("mul32", M.mul32(c[1], c[2]) == c[3], string.format("%d*%d", c[1], c[2]))
end

print("== 2. 确定性 ==")
local kw = M.keywords("Kryx-Secret-Key-2026")
chk("同参两次相同", same_buf(M.stream(kw, 0x12345678, 64), M.stream(kw, 0x12345678, 64), 64))

print("== 3. 雪崩 ==")
local base = M.stream(kw, 0x12345678, 32)
local d1 = bitdiff(base, M.stream(M.keywords("Kryx-Secret-Key-2027"), 0x12345678, 32), 32)
local d2 = bitdiff(base, M.stream(kw, 0x12345679, 32), 32)
chk("key 改 1 字节 → 比特差 35%~65%", d1 > 89 and d1 < 166, d1)
chk("nonce 改 1 bit → 比特差 35%~65%", d2 > 89 and d2 < 166, d2)

print("== 4. 流式前缀一致性 ==")
chk("16 字节 == 64 字节前 16", same_buf(M.stream(kw, 7, 16), M.stream(kw, 7, 64), 16))

print("== 5. 加解密往返 ==")
local samples = {"", "a", "ab", "abc", "abcd", "abcde", "abcdefgh",
                 string.rep("Kryx", 100), "中文测试 UTF-8 多字节字符串 混合 ASCII"}
for i, s in ipairs(samples) do
    local ct = M.encrypt(s, "k" .. i, i * 977)
    local pt = M.decrypt(ct, "k" .. i, i * 977)
    chk("往返 len=" .. #s, pt == s, ("got %q"):format(pt:sub(1, 16)))
end

print("== 6. 密文不等于明文 ==")
local ct = M.encrypt("AAAAAAAAAAAAAAAA", "key", 0)
local all_a = true
for i = 0, 15 do if buffer.readu8(ct, i) ~= 65 then all_a = false end end
chk("全 A 明文不产生全 A 密文", not all_a)

print("== 7. 不同 nonce 产生不同密文 ==")
local c1 = M.encrypt("same plaintext!!", "k", 1)
local c2 = M.encrypt("same plaintext!!", "k", 2)
chk("nonce 1 vs 2 密文不同", not same_buf(c1, c2, 16))

print("== 8. Luau 语义依赖点（在别的语言上会偏） ==")
chk("lshift(x,32)==0", bit32.lshift(0x12345678, 32) == 0)
chk("rrotate(x,33)==rrotate(x,1)", bit32.rrotate(0x12345678, 33) == bit32.rrotate(0x12345678, 1))
chk("bxor(-1.5,0)==0xFFFFFFFF", bit32.bxor(-1.5, 0) == 4294967295)
chk("(-7)%3==2", (-7) % 3 == 2)
chk("math.fmod(-7,3)==-1", math.fmod(-7, 3) == -1)
chk("buffer.writeu8 会 mod 256", (function()
    local b = buffer.create(1); buffer.writeu8(b, 0, 300); return buffer.readu8(b, 0) == 44
end)())

print("== 9. 输出向量（供跨实现比对） ==")
local v = M.stream(M.keywords("Kryx-Secret-Key-2026"), 0x12345678, 32)
local hex = {}
for i = 0, 31 do hex[#hex + 1] = string.format("%02X", buffer.readu8(v, i)) end
print("  " .. table.concat(hex))

print(("PASS=%d FAIL=%d"):format(pass, fail))
if fail > 0 then
    error(("KX1 自测失败 %d 项"):format(fail), 0)
end
