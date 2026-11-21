# sample2.lua 解析报告

> 依据 `AI必读/sample.md`：静态破解代码结构，**不需要破解源码**；搞清楚用了什么混淆技术、什么加密算法、什么控制流混淆即可，用于模仿生成混淆文件。
> 分析前已按要求把样本拆成 **8 个文件**（`part1.lua` ~ `part8.lua`，共 167 个顶层条目，重组与原文逐字节一致，属于必须先拆分阅读再分析）。

## 0. 样本概况

| 项目 | 值 |
|---|---|
| 文件 | `AI必读/sample2.lua` |
| 大小 | 52976 字节，1 行，无注释、无多余空白 |
| 顶层形态 | `return({ ... }):J()(...);` —— 单 return 一个匿名大表，表 `:J()` 后立即调用返回值 |
| 可运行性 | **不可运行**。`AI必读/README.md` 明确说明：所有 samplex.lua 的 payload 已被作者删除，只作混淆外观参考 |
| 条目组成（167 个） | 137 个 `function` 条目 + 15 个 bit32 别名 + 14 个标量别名 + 1 个常量表 `q` |

顶层入口速览（按文件顺序）：`RP,p2,S2,CP,Q2,j2,c,K2,st,j,ZP,c2,D2,x,_2,U2,t2,i2,J,dP,pP,N,mP,D,g2,ut,bP,JP,_,VP,vP,I2,k,fP,aP,M,w,SP,l2,NP,Y2,nP,AP,bt,t,l,h2,n,A2,tP,k2,Z2,gP,W2,T2,KP,m2,u2,Z,OP,i,u,QP,qt,hP,K,L2,GP,P,MP,f2,Q,m,DP,f,TP,h,E,F2,o2,S,N2,LP,y2,y,iP,a2,e2,yP,o,EP,s,qP,rP,B,Y,V2,C,F,z2,e,d,B2,v,p,G2,r2,oP,b,r,R2,uP,V,eP,WP,b2,Xt,T,rt,q2,E2,UP,w2,cP,XP,PP,Jt,d2,Lt,X2,J2,G,zP,q,YP,v2,A,IP,M2,wP,n2,O2,BP,L,O,a,g,x2,U,P2,FP,xP,jP,s2,kP,z,X,HP,_P,H,I,sP,H2,R,lP,W,C2`

---

## 1. 代码结构（骨架）

```
return({
  -- (A) bit32 / 全局 / 字符串库别名注册表（前 16 个标量条目 + 15 个 bit32 条目）
  -- (B) 常量密钥表 q = {9 个 32 位整数}
  -- (C) 137 个方法（method），名字全部是 1~2 个字母/数字/下划线的随机标识符
}):J()(...)
```

### 1.1 入口 `J`（编排器 / Orchestrator）

`J=function(v)local u,m={}; ... end` 做三件事：

1. **构建环境表 `u`**：连续调用 `k → T → B → F → E → y → n → a → R → d2 → f2 → E2 → eP → KP` 等"构建器"函数，把环境的数字键槽位填上（每个槽位放别名、函数、子表、解密后的常量）。
2. **生成被保护程序**：`eP`/`VP` 等构造两个闭包（主 chunk + 子 chunk），`E2`/`T2`/`d2` 把它们挂到环境的数字键上（如 `f[53]`、`f[56]`、`f[59]`、`f[60]`）。
3. **执行**：`h=u[0x3d](h,u[0x10])(v,K,v.s,u[0x4],p,u[45],u[0x2f],u[0x31],u[0B111001],u[58],v.q,u[0X03__d])` —— 以 `setfenv` 风格闭包执行主 chunk（`u[0x3d]` 绑定环境后调用），最后 `return u[0X3d](h,u[0X10])`。

`v` 永远是"大表自己"（method 调用 `v:x(...)`），所有方法之间互调都经过它。

### 1.2 三类运行时角色

| 角色 | 代表 | 职责 |
|---|---|---|
| 环境构建器 | `k/T/B/F/E/y/n/a/j/R/d2/f2/E2/eP` | 创建 env 表、注册槽位、注入位运算子表、装入字节码读取器 |
| 常量解密器 | `H/N/w/m/O/OP/IP/NP/aP/OP/s2/V/g/y/...` | 每个函数还原并缓存 **一个** 隐藏常量（写进 `m[26769]`、`u[818]` 这类数字键） |
| 字节码 VM | `_P`、`Q`、`n`、`X2`、`v2`、`O2`、`dP`、`i2`… | buffer 读取/LEB128、opcode 分派、解释执行 |

### 1.3 `n`：buffer 读取器描述表

```lua
(m)[0X13]=p.readi32; m[0X14]=v.RP; (m)[0B1010__1]=p.readu32;
(m)[0B1011__0]=(p.readf32); m[0X1A]=(p.copy); (m)[0B11001]=p.writeu32; ...
```

把 `buffer.read*/write*` 装进环境，VM 之后只通过槽位访问，不直接出现 `buffer.readu32` 字样。`X2` 是"按 `u[5]=2^32` 缩放、把高低两个 32 位值合并/拆分"的 64 位整数组合读取器；`v2` 是 **LEB128 varint** 解码循环（`u+=((m>127 and m-128 or m)*v); v*=0b10000000`）；`O2/A2/w2` 算解码字节数 `(h-f)/8`。

### 1.4 `_P`：字节码解释器（文件的核心，约 2.1 万字节，占 ~40%）

- 单个巨型函数 `_P=function(v,u,m,f,K,p,h) ... end`
- `repeat ... F+=0x1; until false` 主循环，`F` 是**指令指针**；`J,Y,Z,S,U,n,C` 是操作数/常量/栈表，`a` 是值栈
- opcode `g` 用**嵌套 if/elseif 二叉判定树**分派：统计到 `g==…` 25 个、`g<`/`g>` 区间比较 132 个；**指令号不连续**（0, 4, 31, 52, 67, 70, 76, 85, 88, 97, …, 190），即字节码**指令集被再编号**
- 每个 opcode 主体是内联的栈/寄存器操作（`a[w[F]]=...`、`F=(S[F])` 跳转、闭包创建、`coroutine.yield` 调用点等）；共约 25 个显式 `g==` 分支 + 树状区间分支，覆盖加载/算术/比较/跳转/调用/表操作/闭包/变参等 Lua 语义
- 末尾是 `if P then ... return a[A]() ...` 的收尾 + `"Luraph Script:"` 风格断言错误出口

### 1.5 文件尾部还原出的字符串（全部按 Lua 转义"明文化"，无明文串）

| 源码片段 | 还原 |
|---|---|
| `'stri\x6E\103'` | `string` |
| `"\L\u{75}r\x61\z\x70h \83cr\z \105\zpt:"` | `Luraph Script:` |
| `'in\zte\x72n\z  al\x29'` | `internal)` |
| `":\40\z\x25d+\x29[:\r\n\x5D"` | `: %d+)[:\r\n]` |
| `'<i8'` / `'\60i\z 8'` / `'\x3Ci8'` / `'\t\0\0\0\0\u{000}\0\0'` / `'\5\z  \x00\0\0\0\z\x00\0\0'` | 结构体 unpack 格式 / 8 字节二进制常量 |

**结论：该样本是 Luraph 风格的商业 Lua VM 保护器输出**（VM + 内嵌字节码 + 运行时还原），不是手写压缩。

---

## 2. 字符串混淆与"加密算法"

### 2.1 几乎没有明文字符串

唯一长括号串：`[==[LPH@!!#S5]==]`，在 `a` 里经 `u[0X27](...)` 解码为内嵌 buffer（`u[0X28]`），读取位置是 `u[0B101001]`（偏移槽）。

### 2.2 自定义字符串解码器（非标准算法，自研混合进制）

```lua
p = gsub(p, "\u{7A}", "\!\z!!\33!")          -- 预转义替换
local h,J,Z = {}, 0x0, #p - 4                  -- 前 4 字符为 magic 前缀（"LPH@"）
local b = buffer.create(math.floor(Z/5)*4)     -- 每 5 字符 → 4 字节
for j = 5, Z, 5 do
  local Z = string.sub(p, j, j+4)
  ...                                          -- 带缓存 h[Z] 的查找
  local q,H,C,U,Y = byte(Z,1,5)
  local z = ((Y-0B100001)+(U-0x2_1)*0x55
           +(C-0b1000_01)*0x01C39
           +(H-0X21)*614125
           +(p-33)*0X3_1C84b1)                 -- 底数 '!'（33）的混合进制多项式
  buffer.writeu32(b, J, z);  J += 4
end
return b
```

特点：底数统一为 `!`(33)，系数是 5 个固定 32 位数乘方（1 / 0x55 / 0x1C39 / 614125 / 52200625）；输入前缀 `"LPH@"` 被跳过；结果是 `buffer` 而不是 string。**没有 AES/XOR 之类标准密码，"加密"＝自研混合进制编码 + base‑33 风格查表**。

### 2.3 转义串拼接（错误信息 / 断言）

`\xNN`、`\ddd` 十进制、`\u{...}`、`\z`（吃掉后续空白）四种转义混用，把 `"Luraph Script:"` 这类信息拆成多段再 `..` 拼接，肉眼不可读，但**不是加密**，只是编码。

### 2.4 数字常量"加密"（核心，q 表 + 不透明常量）

`q={19629, 885834035, 3196659159, 2182124722, 2000289173, 2124701452, 1703331282, 1781180127, 69707939}`
（= 0x4CAD, 0x34CCC133, 0xBE8925D7, 0x821094B2, 0x7739FD95, 0x7EA45F0C, 0x6586C5D2, 0x6A2AA6DF, 0x0427A8A3）

还原手法：

1. **负数回绕**：`-4294947532` = `19764 - 2^32`（bit32 运算只保留低 32 位），`-1781180018` = `-(q[8]) + 109`，`-0X7739FD42__` 这类。
2. **q 表参与的多项式**：`f=(-4294869680+(v.MP((v.bt((v.rt(v.q[0B11]-m[0X6908],(m[2236]))),(m[18931]))))))` 之类，每个常量一套独立随机结构。
3. **`and/or` 恒定分支选择子**：`(cond and A or B)`，`cond` 由 q 值经 bit32 比较得出，结果恒定 → 静态无法直接读出选的是哪边（实际总走同一边）。
4. **两级缓存**：`if not K[cachekey] then <还原并写回> else <读缓存> end`（例：`if not(not m[15668])then f=m[0X3d34];else ... end`、`if not K[29007]then K[11874]=(...)...else u=(K[29007])end`）。首次计算、之后直接读——既省时间又把"还原表达式"和"使用点"分离。
5. **缓存键也是密数**：写回用的键 `26769/2236/18944/23129/818/...` 本身也是还原出来的（键槽位不固定）。

`v.q` 只有 `q[1..9]` 被用到，且只出现在这套还原表达式里，**q 表 = 全部隐藏常量的密钥种子**。

---

## 3. 控制流混淆（重点）

### 3.1 哨兵状态码"返回值即状态"的扁平化（最核心）

小函数**不直接返回业务值**，而是返回一个魔法状态码，调用方循环等待期望的码：

```lua
i2=function(...) ... for m=81,0b1011_10__00,0x58 do u,p,f=v:v2(u,f,K,m);
    if p==0X1790 then break; elseif p==0XB1__B5 then continue; end end ... end
dP=function(...) ... repeat p,K,h=v:i2(p,f,K,h); until h<0X80_ ... end   -- 0x80_ = 128
```

常见哨兵（数值 → 十六进制）：`6032=0x1790, 45493=0xB1B5, 37524=0x9294, 61693=0xF0FD, 63283=0xF733, 46144=0xB440, 25990=0x6586, 25985=0x6581, 33004=0x80EC, 58438=0xE446, 51651=0xC9C3, 20480=0x5000, 40933=0x9FE5, 45007=0xAFCF, 23266=0x5AE2, 8274=0x2052, 7935=0x1EFF, 34314=0x860A, 16625=0x40F1, 0/-1/-2`。

状态码当返回值向上冒泡，层层 `repeat until` 接力，形成**跨函数的扁平化控制流**。

### 3.2 显式状态变量 + 无限主循环

```lua
D2=function(v,u)local m,f,K,p,h=99;
  while true do
    if m==102 then ... u[0B10__1001]=(u[41]+p); m=0B01101;
    elseif m==0B1101 then return -2,h;
    elseif m==0B1100011 then p=u[53](); m=(0X66); h=u[0X32](...) ... end
  end ... end
```

`VP` 的状态链（实测按执行顺序）：`Z=115 → (Z==0b1110011 分支) → 54(0b110110) → 经 vP 得到 29(0x1d) → (0X01d 分支) → 0x58 → (0X58 分支) → 0x57 → (0x57 分支) → 0x4A → break`。`nP`、`eP`、`k2`、`U2`、`kP`、`x2` 等共 **37 个 `while true`、39 个 `repeat until false`**。`until false` 恒假 → 只能靠内部 `break/return/continue` 退出，模拟 goto 和任意跳转。

### 3.3 恒假循环"while 恒真"写法

`while-(-0B1011110)do ...`（`-(-94)`=94，恒真）、`while (0B1011011) do`、`repeat ... until false` 共 39 处、`H2`、`W2`、`UP` 等——循环条件本身是不透明常量。

### 3.4 continue/break 密集使用

`continue` 96 次（Luau 扩展）。循环体尾部常见 `if cond then continue; else if ... then break end end`，实现"多出口尾合并"，破坏正常的结构化可读性。

### 3.5 不透明谓词 / 伪分支

- `if not(...)` **152 次**；`not(not x)` 双重否定展开（`if not(not m[0X1b79])then h=f[7033];else h=v:NP(f,h);end`）
- 常量谓词：`if 0B1011011 then`、`if not(0B10101011)then else v:EP(f);end`、`if not(t)then else ... end`、`if 0X75 then`、`if f-f`（恒 0）
- 空 `then` 分支：`else if K~=-0X2 then else return-0x002,f;end;end`（只有 else 在工作）
- `if not(u<=0b110100__)then ... else ... end`、`if not(h<=8)then` 这类永远取值相同的比较

### 3.6 二叉判定树 opcode 分派

`_P` 里对 `g` 的判断写成**嵌套 if/elseif 近似平衡树**（`g<0X2F`、`g<0B1001000`、`g>=0X59`、`g>=0B1011100`…，共 132 次区间比较 + 25 次 `g==…`），叶子是各 opcode 实现（约 25 个密集态，指令号非连续）。效果：

- 无 `switch`/表分派痕迹，反编译器难以还原"指令表"
- 判定顺序与 opcode 数值本身被随机化 → 每次输出结构都不同（满足"生成文件结构不能相似"）

### 3.7 死代码 / 伪代码

- `t2=function(v)while true do return-0B1;end;return 61693;end`（`return` 之后还有 `return 61693`，不可达）
- 空函数占位：`u2=function(v)end`、`FP=function(v)end`、`cP=function(v)return;end`
- `S2` 恒返回 8、`o2` 恒返回 `0b1000111`、`A2` 返回 46、`P2/r2` 恒等、`fP` 返回 `v[46]`、`SP/gP/jP/yP/...` 全是 `f[idx]=v` 型搬运
- `else` 只有一支有内容、`if X then nil else ... end`

### 3.8 LEB128 / 变长解码循环

`v2`（varint：`(m>127 and m-128 or m)*v; v*=0b10000000`）、`X2`（两 32 位重组 64 位）、`q2`（带状态读取）、`J2`/`l2` 等——被保护程序的整数解码全手写，配合 VM 使用。

---

## 4. 变量 / 命名 / 字面量混淆

| 手法 | 实例（样本事实） |
|---|---|
| 随机标识符 | `u2,f2,X2,zP,bP,qP,KP,XP,OP,QP,TP,WP,YP,_P,NP,QP,Z2,g2,m2,...`（约 150 个 1~2 字符名） |
| 寄存器式参数复用 | 每个函数参数槽位永远是 `v,u,m,f,K,p,h,J,...`（最多 22 个），机器生成、人不可读 |
| self 统一 `v` | method 互调 `v:x(...)`；env 表用 `u`/`f`/`m` 混用 |
| 数字键环境槽位 | `f[0X3e]`、`u[26769]`、`m[0X5F7A]`… 键本身是不透明常量 |
| 字面量格式混用 | 十六进制 1109 个（151 个含 `_`）、二进制 481 个（139 个含 `_`）、十进制大常量 46 个、带下划线字面量共 290 个 |
| 前缀大小写混用 | `0X`/`0x`、`0B`/`0b` 随机；含前导零（`0X001D`、`0X4__086`）、下划线（`0x6__8`、`0b1__101`、`0X0020`）、负号与 `+` 链 |
| 表达式通胀 | `-(-0B1)`、`(v%0X8)`、`h-h%0X1`、`-0XBB)^m`、`((u-v)/0B1__000)`、`(f-f)` |
| 常量回绕 | `x - 2^32` 形式负数（见 §2.4） |

---

## 5. 全局 / 库访问混淆

所有 builtin **不直接写全局名**，而是先别名化：

- bit32：`RP=band, CP=countlz, st=bor, mP=lshift, ut=lrotate, bt=rrotate, rt=rshift, qt=countrz, Jt=bxor, MP=bnot, P=bit32`（部分条目重复别名：`x=countlz, l=bor, f=lshift, X=bxor`，使每个使用点的名字随机）
- 标准库/全局：`t=unpack, u=unpack, Z=error, i=table, o=string.match, v=string.char, b=string.sub, Xt=string.unpack, Lt=string.byte, L=string.gsub, r=buffer, d=setfenv`，以及 `getfenv/tostring/pcall/select/type/coroutine.yield/coroutine.wrap/unpack` 等全部通过环境数字键调用
- 函数体里真正出现的全局 token 极少（`coroutine.yield` 1 次、`coroutine.wrap` 1 次、`pcall` 1 次、`tostring` 1 次、`getfenv` 1 次、`type` 1 次、`select` 1 次、`error` 1 次、`string.*` 6 次——全在别名注册区和错误片段里）

---

## 6. 加密 / 保护方案总结

| 层 | 技术 | 样本体现 |
|---|---|---|
| 容器 | 单 return 匿名表 + `:J()(...)` 立即调用 | 顶层无任何 `loadstring`/`require`，VM 内嵌于闭包 |
| 字节码 | buffer 字节数组 + 自定义 LEB128/varint 读取 + opcode 再编号 | `n/X2/v2/O2/dP/_P`；opcode 密集态不连续（0,4,31,…,190） |
| 字符串 | 自研 base-33 混合进制 + buffer 写入；错误串用 Lua 转义拼接 | `[==[LPH@!!#S5]==]` + u[0x27] 解码器；`"Luraph Script:"` 片段 |
| 常量 | q 表（9×32bit）+ 位运算多项式 + `and/or` 恒定分支 + 写回缓存 | `N/w/H/NP/...` 等"解密器函数"，缓存键也是密数 |
| 控制流 | 哨兵状态码跨函数扁平化 + `while true`/`repeat until false` + 二叉判定树分派 + 152 处 `if not` 不透明谓词 | `D2`、`VP`、`i2`、`dP`、`_P` 等 |
| 命名 | 随机 1~2 字符名 + 寄存器式参数复用 + 数字键 env 槽位 | 全文件 |
| 死码 | 不可达 `return`、空函数、恒等函数、空 `then` | `t2/u2/FP/cP/S2/o2/A2/P2/r2/...` |

**没有发现**：标准对称加密（AES/RC4/XOR 流）、`string.dump` 明文、`load` 动态加载（执行入口是直接闭包调用）、网络/文件 IO（`io.`/`os.`/`math.` 均未出现）。

---

## 7. 调用关系图（静态还原）

```
return (大表):J()(...)
└─ J 编排器
   ├─ k/T/B/F/E/y/n        环境初建（槽位 1..62、bit32 子表 f[6]/f[7]、reader 描述表）
   ├─ j/R/Z2/gP/...        环境封尾/清理（删除临时键）
   ├─ a                    常量解密 + payload 还原；注册 u[0x27] 字符串解码器
   │   └─ [==[LPH@!!#S5]==] → buffer u[0x28]（偏移槽 u[0B101001]）
   ├─ d2                   构建 f[41/58]（coroutine.yield、X2 读取器）
   ├─ f2                   f[53]=当前位置函数、f[54]=nil→function(行号函数)、f[56]=table.move、f[57]=函数
   ├─ E2                   f[58]=function（=pcall 包装的错误出口 x2）、f[59]=T2（断言出口）、f[60]=function(...)#/长度包装
   ├─ eP                   f[61]=nil、f[62]=nil、注册 f[6][7..0x16] = rshift/lshift/lrotate/band/unpack、
   │                       常量还原（10232、4541、……），循环调用 _P 直至拿到 0X5aE2
   ├─ KP                   给 f[6] 注册 bit32 子集（f[6][0xF]=bor, f[6][8]=bnot, f[6][0x10]=lshift, f[6][0xC]=string.unpack, f[6][0x6]=countlz）
   ├─ n                    m[19..27] = buffer.read*/write* 描述表（p 为 buffer 对象）
   └─ h = u[0x3d](h, u[0x10])(v, K, v.s, u[0x4], p, u[45], u[0x2f], u[0x31], u[0B111001], u[58], v.q, u[0X03__d])
        └─ 主 chunk 以 setfenv 绑定环境后执行（被保护程序从这里开始跑）
```

（`_P` 内部：`repeat … until false` 主循环，`F` 指令指针，opcode `g` 二叉判定树，值栈 `a`，操作数表 `J/Y/Z/S/U/n/C`。）

---

## 8. 模仿生成时需要注意的外观清单

1. 顶层必须是 `return({...}):唯一入口()(...)` 的单表达式形态，所有代码在一个匿名大表里。
2. 表内顺序：先别名注册（bit32/全局/字符串库/buffer），再 q 密钥表，再 100+ 个方法；条目之间用 `,\n` 紧贴排列，无空行。
3. 名字随机 1~2 字符 + 数字 + `_`；参数槽位永远 `v,u,m,f,K,p,h,J,Z,b,j,H,C,U,Y,z,n,S,w,a`。
4. env 全部用数字键（含 `0X`/`0B` 混合格式化），键也是密数。
5. 每个隐藏常量配一个"还原器函数"，结构为 `-4294967358 + (bitop(q…) …)` 形式的负数回绕常量 + `(cond and A or B)` + `if not cache then write else read end`，且每次生成结构必须不同。
6. 控制流：哨兵状态码 + `repeat until false`/`while true`/`continue` + 151 处级别的 `if not(...)`；opcode 用二叉 if/elseif 树分派且号段随机。
7. 字面量全格式混用 + `_` 分隔 + 负数回绕常量；长字符串只能用长括号 `[==[...]==]` 且内容经自研混合进制解码。
8. payload 内嵌为 buffer 字节数组（本样本已删除 payload，生成器需按同样框架自行嵌入）。
9. 不使用：`loadstring/load`、`require`、明文字面量、`switch` 表分派、连续 opcode 编号。
10. 入口函数（J 类）负责：建 env、装 reader、建闭包、setfenv 绑定、立即调用。

---

## 9. 局限与说明

- 样本 payload 已被作者删除，本报告**只覆盖静态结构**，不验证运行行为，也不还原被保护程序的业务逻辑。
- q 表参与常量还原的**数学恒等式未逐一求解**（样本中每个还原器结构都不同，属机器生成，逐个解意义不大，且超出"结构破解"范畴）；只确认了手法（负数回绕 / 位运算多项式 / 恒定 and‑or 分支 / 缓存写回）。
- opcode 判定树覆盖的**具体语义映射表**（哪个 g 号做什么）未逐一反汇编；已确认其为 Lua 字节码解释器（含 varint 读取、64 位重组、闭包、coroutine.yield、table.move、setfenv 等）。
- 结论"Luraph 风格"来自还原出的 `Luraph Script:`、`string`、`internal)`、`: %d+)[:\r\n]`、`stri\x6E\103` 等断言片段，属高置信度归因，非官方声明。
- 拆分 8 个文件 `part1.lua`~`part8.lua`（167 条目逐条标注 `===== ENTRY 名字 =====`，重组与原文逐字节一致）仅用于阅读，不入库。

## 10. 数字速查（供对照）

```
q = {0x4CAD, 0x34CCC133, 0xBE8925D7, 0x821094B2, 0x7739FD95,
     0x7EA45F0C, 0x6586C5D2, 0x6A2AA6DF, 0x0427A8A3}
统计：函数条目 137 / bit32 别名 15 / 标量别名 14 / 常量表 1
      continue 96 / repeat 40（until false 39）/ while true 37 / if not( 152 / elseif 55
      十六进制字面量 1109（含 _ 151）/ 二进制字面量 481（含 _ 139）/ 带下划线字面量 290
      方法互调 v: 135 次 / bit32. 直接引用 14 次 / 数字字段键 [N]= 252 次
      _P 解释器 21216 字节（约 40%），g== 25 个、区间比较 132 个、opcode 密集态非连续
```

---

## 11. 控制流复刻进度（2026-11-21 更新）

按 §3 的真实骨架，把 `src/VM/cf_wrap.rs` 的语句包裹器改写成 sample2 的形态：

| 手法 | 样本做法（§3） | 生成器现在的做法 |
|---|---|---|
| 哨兵状态死循环 | `repeat if h==0x50 then …;break;else if h~=… then h=0X50;end;end until false;` | `wrap_stmt` 有 40% 走 `state_machine()`：随机状态变量 + 3~5 个状态 + 真实 `==`/`not(…~=…)`/`not(not(…))` 判断 + `continue` 迁移 + `break` 出口，状态迁移值生成期精确推算 |
| `while true do if X==N` 状态链 | `D2`、`VP`、`i2` | 同上的 `state_machine_while()` 变体，守卫 `true` / `not(<恒假>)` / `-(-94)` 混用 |
| `repeat … until false` | 39 处 | 现在有真实产出（`until false` 25~31 处） |
| `continue` | 96 处 | 93 处 |
| `elseif` / `else if` 混用 | 55 处 elseif | 95 处 |
| `if not(...)` | 152 处 | 112 处 |

### 顺带修掉的三个真实缺陷（不修就没法生成这类控制流）

1. **`continue` 跳转目标从未被回填**（`src/compiler/codegen.rs`）。
   `add_continue_jump` 只把跳转链挂进 `block.continue_list`，四个循环编译器
   （`while` / `repeat` / 数值 `for` / 泛型 `for`）从来没有调用过 `patch_list`，
   于是 `continue` 的 JUMP 偏移停留在未回填状态 → 数值 `for` 里 `continue`
   直接死循环。新增 `Compiler::patch_continue_list(target)` 并在四处补上：
   `while` → 条件重算处、`repeat` → `until` 条件处、`for` → `ForLoop`/`TForLoop` 处。
2. **压缩器的 AST 不认 `continue`**（`src/compressor/`）。
   解析 `continue` 时报 `期望获得 '='`。给 `LastStmt` 加了 `Continue` 变体
   （parser / scope / codegen 三处同步），现在 `continue` 能安全穿过压缩步骤。
3. **状态机里 `return` 之后不能再补语句**。`wrap_stmt` 先检测 BODY 是否自带
   `return`/`break`/`continue`，有就只做单趟包裹，避免 `return x;break;` 这种非法序列。

### 试过但放弃的写法

`if not(cond) then else BODY end` 这种「空 then、else 干活」的反写分支（样本
`then else` 93 处）**在 BODY 含 `local` 时不成立**：BODY 被塞进 `if`/`repeat`
的新作用域后，外层同名 `local` 被遮蔽，实测失败率从 3/30 跳到 20/30。
已移除该分支，只保留语义安全的状态机包裹。
