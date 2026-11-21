# sample2.lua 包装形式全清单（真实代码）

> 依据：`AI必读/sample2.lua`（52,976 字节，单行，无换行，无注释）。
> 本文所有代码片段都是原文直接摘录，未改写。
> 结构总览：`616` 个顶层条目中 `143` 个是 `key=function(...)`，其余是别名/常量/表。
> 关键字计数：`if` 590、`else` 513、`end` 845、`return` 197、`not` 201、
> `and` 104、`or` 79、`while` 39、`repeat` 40、`for` 55、`local` 80、
> `elseif` 55、`function` 161。**没有任何注释**，**没有 `local function`**。

---

## 1. 顶层返回壳 + 立即调用

整个文件只有一个表达式：`return (表):方法()(...)`。

```lua
return({RP=bit32.band,p2=function(v,u,m,f,K,p)if u>23 then p=m[0x0020](f);else K={v.S,v.S,v.S,nil,nil,v.S,v.S,v.S,v.S,v.S,nil};end;return K,p;end,S2=function(v,v)v=(0X8);return v;end,CP=bit32.countlz,
```

结尾：

```lua
C2=function(v,v,u,m,f,K,p)if not(v>0x3e)then p=f[17][m];else K=#p;(p)[K+0X1]=u;end;return K,p;end}):J()(...);
```

三种包装要点：
- 入口是 `return(...)` 而不是 `local x=...`：模块直接 `return` 一张表。
- 表里的方法用 `:` 调用：`({...}):J()`，即 `J` 以 `self = 整张表` 运行。
- 结果再立刻用 `(...)` 调用：`J()` 返回的**函数**被就地调用，参数是 `...`（模块 `...`）。

---

## 2. `select` 的包装

**全文只有 1 处 `select`**，它不直接调用，而是**写进一个槽位字段里存起来**：

```lua
B=function(v,u,m,f)if u>0B1011110 then(m)[1]=select;
```

同一函数里配套的"用槽位当寄存器"的写法（`m[1]` 存 `select`，其它槽位存中间值）：

```lua
if u>0B1011110 then(m)[1]=select;if not f[26888]then f[0x78c7]=(83+(v.CP(v.q[0B110__]+v.q[8]+v.q[0B1__0]>v.q[0B101]and v.q[0X5]or v.q[6])));u=(75+(v.qt((v.qt(u>=v.q[0X8]and v.q[6]or v.q[0b10]))~=v.q[0X9]and v.q[0X4]or v.q[0X6])));f[0X6908]=(u);else u=(f[0X6908__]);end;
```

注意这里的几个手法：
- `(m)[1]=select`：内建函数**不是**取别名变量，而是塞进表槽位；
- `f[0x78c7]` / `f[0X6908]`：随机数字字段名当缓存；
- `(83+(...))`：常数 + 一长串壳方法调用；
- `a>=b and c or d`：用 and/or 当三元运算符。

---

## 3. 其它内建函数/库的包装（全部是"壳字段别名"）

顶层表里直接挂别名，**名字 1~2 字符**，正文只通过 `v.xxx` 访问：

```lua
RP=bit32.band,CP=bit32.countlz,st=bit32.bor,x=bit32.countlz,mP=bit32.lshift,
ut=bit32.lrotate,bt=bit32.rrotate,t=unpack,l=bit32.bor,Z=error,i=table,u=unpack,
qt=bit32.countrz,MP=bit32.bnot,f=bit32.lshift,o=string.match,v=string.char,
b=string.sub,r=buffer,Xt=string.unpack,rt=bit32.rshift,Jt=bit32.bxor,
Lt=string.byte,L=string.gsub,X=bit32.bxor
```

补充：`coroutine.yield`、`pcall`、`type`、`tostring`、`bit32.rrotate` 等
**不取别名**，而是直接写进某个表的数字槽位：

```lua
elseif K==64 then u[0X1B]=pcall;
(f)[0X0033]=coroutine.yield;
(u[0B110])[0x9]=v.X;            -- 槽位里放壳别名
(u[0x6_])[13]=v.qt;
u[6][0XC]=v.Xt;
(m)[0X8]=v.u;(m)[9]=v.X;m[0xa]=nil;
(m)[0X13]=p.readi32;m[0X14]=v.RP;(m)[0B1010__1]=p.readu32;m[0B1011__0]=(p.readf32);m[0B10111]=(nil);m[24]=nil;
```

还有一类是"槽位清空"包装（相当于作用域回收）：

```lua
(v)[0B011100]=nil;v[0B11101]=nil;(v)[0X1e]=nil;(v)[31]=(nil);v[0x20]=(nil);(v)[33]=(nil);v[0X22]=nil;v[35]=nil;
(u)[0X1]=(nil);(u)[0b10]=(nil);u[0x3]=(nil);u[0B100]=(nil);
```

---

## 4. 重复参数名（签名伪装）

139 个顶层函数里只有 20 种签名，因为**参数名被随机重复**：

```lua
19x  function(v,v,u)
16x  function(v,u,m,f,K)
15x  function(v,u,m,f)
15x  function(v,v,u,m)
12x  function(v,v)
```

真实代码：

```lua
S2=function(v,v)v=(0X8);return v;end,
r2=function(v,v)return v;end,
j2=function(v,v,u)u[0X8]=v;end,
c=function(v,v,u)v=u[0X6B6];return v;end,
yP=function(v,v,u,m)(u[0X1_1])[m]=(v);end,
a2=function(v,v,u,m)m[u]=(u+v);end,
```

（Luau/Lua 允许参数重名，最后一个生效 ⇒ 前面的形参是纯噪声。）

---

## 5. 样板/填充函数（真实存在的四种）

```lua
u2=function(v)end,                       -- 空函数
FP=function(v)end,                       -- 空函数
r2=function(v,v)return v;end,            -- 恒等
P2=function(v,v)return v;end,
c=function(v,v,u)v=u[0X6B6];return v;end,   -- 只读表一位
L2=function(v,v,u)v=u[0x30EE];return v;end,
W=function(v,v,u)u=(v[0X49F3]);return u;end,
e=function(v,v,u)u=(v[18179]);return u;end,
QP=function(v,v,u)u=(v[53]()-61322);return u;end,   -- 减法伪装
OP=function(v,v,u)u=(0x38+((v[0X4c02]-v[18451]<v[18931]and v[0X8e9]or v[0x3d6_F])+v[1718]-v[23114]));v[11862]=u;return u;end,
b2=function(v,v)v[0X29]=v[0b101001]+0x2;end,        -- 自增伪装
R2=function(v,v,u,m)m[v]=(v-u);end,
v2=function(v,v,u,m,f)if not(f<0XA9)then v*=0b10000000;return v,6032,u;else u+=((m>127 and m-0X0080 or m)*v);return v,0Xb1B5,u;end;end,
D=function(v,v)v[0X4_]=function(...)return(...)[...];end;end,   -- 变参转发
s=function(...)(...)[...]=nil;end,                               -- 变参空操作
```

---

## 6. 立即调用函数（IIFE）：8 处 `(function(`

```lua
GP=function(v,v,u,m)v=(function(...)return(...)();end);u=m();return v,u;end,
```

```lua
if u==0x79 then(f)[0B110110]=(function()local K=f[53]();for p=0X59,0XAC,0B1001100 do if not(p<=0b1011001)then return K;else if K>=f[34]then return K-f[0X3];end;end;end;end);
```

```lua
else K=(function()local f,K;f,K=v:F2(u);if f~=-0b10 then else return K;end;end);break;
```

```lua
(u)[60]=(function(...)local v=u[0X1]("\#",...);if v~=0 then else return v,u[0B100101];end;return v,{...};end);
```

```lua
f[0X34]=(function()return(v:X2(f));end);
```

写法要点：IIFE **不加括号调用**（`(function()...end)` 只是取出函数值存进槽位），
真正的调用点在别处；也有 `(function(...)return(...)();end)` 这种把 `...` 原样转发的。

---

## 7. 方法调用（`v:xxx(...)`）：135 处

正文几乎不直接调用函数，而是通过壳 `self` 派发：

```lua
f=v:E(u,f);
f,K=v:F(K,u,f,m);
v:j(u);
f=v:a(u,m,p,f);
v:R(u);
f=v:d2(f,K,u,m);
p,h,K,f=v:eP(K,p,u,f,m,h);
f=v:IP(m,f);
f=v:aP(m,f);
E,w=v:bP(Z,U,j,a,m,J,n,f,w,K,Y,b,u,p,H,z,S,h,C);
```

---

## 8. `while true` / `repeat ... until false` 包装

**`while true` + 双出口**（39 处 `while`）：

```lua
rP=function(v,u,m,f,K,p,h,J,Z,b,j,H,C,U,Y,z,n,S,w,a)local E;while true do E,w=v:bP(Z,U,j,a,m,J,n,f,w,K,Y,b,u,p,H,z,S,h,C);if E==0x2052 then break;else if E~=7935 then else continue;end;end;end;return w;end,
```

**`repeat ... until false`**（40 处 `repeat`）+ 显式 `continue`：

```lua
p=0X2c;else if p<0B1000001 then return-1,u;end;end;until false;
```

```lua
h=0X50;end;end;until false;
```

```lua
repeat p,m=v:B(m,f,u);if p==0x80Ec then break;
```

---

## 9. `for` 循环当 `if` 用（24 处带步长）

循环体里只命中一次，靠 `break` / `continue` 当 `if / else`：

```lua
for J=0x44,0X85,0X41 do
for J=0x11_,0b11111111,0X7__b do
if not(J<0B10001100)then K,f=v:H2(u);if K==37524 then break;else if K~=-0X2 then else return-0x002,f;end;end;else K=v:t2();if K==61693 then continue;else if K==-1 then return-0X01;end;end;end;
```

```lua
for K=0X4F,0XC7,120 do if K==0B1001111__ then m,f=u[48](),u[0x30]();
```

```lua
for h=0X6_0_,0b110111_1,15 do if h==111 then else if h==0B1100000 then u=v:TP(u,f,m,K);end;end;end;
```

---

## 10. "缓存槽位"包装（`if not f[K]` / `if not(not f[K])`）

这是最核心的**记忆化包装**：第一次算、之后直接读。

```lua
if not f[26888]then f[0x78c7]=(83+(v.CP(v.q[0B110__]+v.q[8]+v.q[0B1__0]>v.q[0B101]and v.q[0X5]or v.q[6])));
```

```lua
if not(not m[15668])then f=m[0X3d34];else f=(-4294869680+(v.MP((v.bt((v.rt(v.q[0B11]-m[0X6908],(m[2236]))),(m[18931]))))));(m)[15668]=(f);end;return f
```

```lua
if not(not m[27201])then f=(m[27201]);else f=v:aP(m,f);end;continue;end;
```

```lua
if not(not f[0X4C02])then u=f[19458];else u=v:B2(f,u);end;return u;end,
```

---

## 11. 数值计算包装（`v.q` 常量表 + and/or 三元）

表 `v.q` 是 9 个常量的元组，所有算术都用它做操作数：

```lua
q={19629,885834035,3196659159,2182124722,2000289173,2124701452,1703331282,1781180127,69707939},
```

真实计算式（84 处 `v.q[`）：
```lua
f[0x78c7]=(83+(v.CP(v.q[0B110__]+v.q[8]+v.q[0B1__0]>v.q[0B101]and v.q[0X5]or v.q[6])));
u=(75+(v.qt((v.qt(u>=v.q[0X8]and v.q[6]or v.q[0b10]))~=v.q[0X9]and v.q[0X4]or v.q[0X6])));
u[27048]=(0b1011110+(v.qt((v.CP(v.q[2]))+v.q[0X1]>=m and u[0X7ad7]or u[0X6891])));
m=-0XC+((u[0X67Fb]-v.q[7]-u[26888]<v.q[0B10]and u[0x3d1e]or u[0X6891])+u[32740]);
```

样本招牌写法「负常数 + 字母噪声链」：
```lua
e=-285+(e+g-g+g+g);
e=(-0B01_0100+((K[0X6][0X7](e-g,(30)))+e+e));
_=-4294967258+((K[0x6][0x8](g>g and _ or _))+g+_);
```

复合运算符（`+=` 23 / `-=` 11 / `*=` 5 / `/=` 1 / `%=` 1）：
```lua
K+=1;
f-=u[0x5];
v*=0b10000000;
u+=((m>127 and m-0X0080 or m)*v);
r-=_;
R*=r;
_+=L;
r+=_;
G-=s;
r%=_;
R+=1;
J+=0B100__;
```

---

## 12. 解包后立即调用（`unpack` 双用）

```lua
h=u[0X3d](h,u[0X10])(v,K,v.s,u[0x4],p,u[45],u[0x2f],u[0x31],u[0B111001],u[58],v.q,u[0X03__d]);
return u[0X3d](h,u[0X10]);
```

`u[0X3d]` 是表里的方法（等价 `table.unpack` 或 `unpack`），
先 `unpack(h, u[0x10])` 得到一个函数，再就地 `(...)` 调用它。

同一手法的变参版：

```lua
D=function(v,v)v[0X4_]=function(...)return(...)[...];end;end,
s=function(...)(...)[...]=nil;end,
```

`return(...)()` 这种"把 `...` 原样当地址/调用"是 sample2 的标志性语法糖。

---

## 13. 主初始化器 `J` 的包装链

`J` 是唯一的"主函数"，体内全是顺序方法调用 + 一个 `while true`：

```lua
J=function(v)local u,m={};m=v:k(m,u);local f,K;K,f=v:T(m,f,u,K);f,K=v:F(K,u,f,m);f=v:E(u,f);f=v:y(f,K,u,m);local p;p,f=v:n(f,u,m,p,K);v:j(u);f=v:a(u,m,p,f);v:R(u);f=v:d2(f,K,u,m);f=v:f2(f,m,u);f=v:E2(u,f,m);local K,p,h;p,h,K,f=v:eP(K,p,u,f,m,h);
```

特点：
- 局部变量**先声明后赋值**（`local f,K;` 再 `K,f=v:T(...)`）—— 制造大量多返回值；
- 初始化序列是 `v:k / v:T / v:F / v:E / v:y / v:n / v:j / v:a / v:R / v:d2 / v:f2 / v:E2 / v:eP`；
- 最后的 `while true` 只做状态码三分支（`>` / `<` / `==` 三个支路，分别 `break` / `continue` / 继续）。

---

## 14. 其余微观包装手法汇总

| 手法 | 真实样例 |
|---|---|
| 常数包括号 | `v=(0X8);` `u=(17);` `m[0x2]=v.b;` |
| nil 也是括号 | `(v)[0X0033]=nil;` vs `v[0X22]=nil;` 混用 |
| 数字前缀 `0X0_` + `_` 分隔 | `0b110__00011__`、`0X001D`、`0b11101__1` |
| `not(not x)` | `if not(not m[27201])then` |
| `and/or` 当三元 | `(m>127 and m-0X0080 or m)` |
| 赋值链拆散 | `local u,Z=0x7_3_;` 后接 `while true do` |
| 方法名 1~2 字符 | `v:bP`、`v:H`、`v:hP`、`v:TP`、`v:aP`、`v:i2`、`v:F2` |
| 字段名随机数字 | `f[0x78c7]`、`f[0X6908]`、`m[27201]`、`u[27048]` |

---

## 15. 与本项目的对照（2026-11-18 实测）

同一套正则统计 `sample2.lua` 与 `examples/print.obfuscated.lua`
（2026-11-18，完成第 3/4/5/6 类之后）：

| 包装形式 | sample2 | 本项目 | 状态 |
|---|---|---|---|
| 顶层 `return({...}):X()(...)` 壳 + 链式调用 | 1 | 0 | **缺**（壳被拆成 `local S=({…})` + 前导 IIFE + `return S:m(...)`） |
| 内建/库别名挂在表字段上（`X=bit32.bxor,i=table`） | 20 | 25 | 有 |
| 重复参数名（`function(v,v,u)`） | 63/139 | 13/39（形参≥2 的函数里约 35~40%） | 有 |
| IIFE `(function()...end)` | 8 | 3~7（`do … end` 包裹） | 有 |
| 变参空转 `function(...)(...)[...]` | 1 | 2 | 有 |
| 空函数 `function(v)end` | 2 | 2~4 | 有 |
| 恒等函数 `function(v,v)return v;end` | 2 | 0~1 | 有 |
| 槽位清空连写（`v[k]=nil;` ×N） | 有（8 条连写） | 有（填充函数内） | 有 |
| 只读/只写槽位的填充函数 | 有 | 有 | 有 |
| `while true` 状态机 | 37 | 18 | 有 |
| `repeat ... until false` | 39 | 34 | 有 |
| `for` 当 `if` 用（带步长） | 25 | 6 | 有但稀 |
| `select` 写进槽位 | 1 | 1 | 有 |
| `pcall` 写进槽位 | 1 | 1 | 有 |
| `coroutine.yield` 写进槽位 | 1 | 0 | **缺** |
| 缓存槽位 `if not f[K]then ... else ...` | 1 | 0 | **缺**（第 10 类，待做） |
| `and/or` 当三元 | 69 | 413 | 有（偏多） |

本轮已补齐：第 3 类（内建别名）、第 4 类（重复形参）、第 5 类（样板填充函数）、
第 6 类（IIFE）。仍未做：**第 10 类缓存槽位**（记为下一轮）。

结论：剩下的外观差距主要是**壳的调用形态**（sample2 是 `return({...}):J()(...)`，
本项目是 `local S=({…})` + `return S:m(…)`）与**缓存槽位**这一记忆化包装。
两者都不改变语义，但 sample2 的观感相当程度来自它们。
