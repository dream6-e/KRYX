# KRYX

纯 Rust、无外部依赖的实验性 Luau 混淆器。现有第一阶段寄存器 VM 仅支持很小的语法子集，**尚不能混淆任意 Luau/Roblox 程序，也尚未达到与 sample1.lua 高度相似的完整结构**。不支持的代码会报错，不写输出。

## 实验性语法解析

```sh
cargo run -- --check test.lua    # 只读取和解析，不执行、不写文件
cargo test --offline             # 本地单元及集成测试
cargo run -- test.lua            # 支持的输入输出同目录 test.K.lua
cargo run -- --seed 5122438661592891 test.lua # 可复现的 16 位十进制种子
```

`--check` 报告首个词法/语法错误所在行列，列按字节计算。`kryx::parser::parse(&[u8])` 返回的 `SyntaxTree` 保留原始字节、含空白与注释的完整 token 序列以及带半开字节区间和子节点的 AST。AST 区分表达式优先级、赋值目标和值、表字段、方法字段、类型包和导出类型等；`Node` 的克隆、比较和销毁使用迭代方式，调试输出只显示当前节点和子节点数量。解析器涵盖控制流、函数、表、类型、泛型、插值字符串、属性、条件绑定及部分作用域限制等。Roblox API 在语法层面只是普通标识符、索引和调用，不检查具体 API。

库默认使用当前实现所对应的 Luau 默认语法；例如可用 `parse_with_options(source, ParseOptions { while_local: true })` 显式启用实验性的 `while local` / `while const`。CLI `--check` 使用默认选项。其他非默认或未来的 Luau feature flags 未完整建模。

**这仍不是完整兼容性证明，也不是官方编译器的替代品。** 不做类型检查、执行、完整编译期校验或错误恢复；可能接受无效代码或拒绝有效代码。为避免忽略输入的剩余部分，内嵌 NUL 字节会被拒绝；对照的官方解析器会在此处终止输入。每次解析在 64 MiB 栈的 scoped worker 中执行，递归深度限制为 1000；创建线程可能失败，极端输入仍可能受资源限制。`--check` 成功不能证明源码可编译、可运行或行为正确。

### 第一阶段 VM 混淆器

目前仅支持顶层 `local`/`const`（无类型注解）、未被局部名称遮蔽的全局 `print(...)` 语句、`return`，以及已声明局部变量、`nil`/布尔值、精确范围内的整数、无转义短字符串、括号、基本算术、拼接、比较和 `not`/取负/长度运算。允许多变量声明和多返回，保留返回与打印中的尾部 `nil`。浮点字面量、转义或长字符串、赋值语句、其他函数/全局调用、表、分支、循环、短路逻辑、闭包及其他语法均会拒绝；资源限制及解析器自身的限制也适用。输出不覆盖已有文件，需先手动移走或删除旧输出。以 `-` 开头的文件名可用 `cargo run -- --check -- -file.lua` 或 `cargo run -- -- -file.lua` 指定。

生成器采用借鉴样本的外层表和 `R0` 初始化、带缓存的 Base85 风格分组、变长整数、并行指令数组、闭包构造器、比较树分派和 `pcall` 包装；这是独立实现，**不是 sample1 格式的完整复刻，也不是加密算法**。需要运行环境提供标准 Luau 的 `bit32`、`string.pack`、`table.create`、`getfenv`、`unpack` 等库。运行时错误对象会经包装重新抛出，错误位置和栈信息不保证与原程序相同；复杂自定义环境及 Roblox 运行时尚未实际验证。

默认从系统随机源生成 **16 位十进制**种子并在命令行打印；`--seed` 可重现。种子会改变 opcode 分配、分派树、初始化状态表达式及字段顺序，但目前整体骨架仍相似，随机性尚不能满足“每次结构完全不同”的最终目标。Unix 使用 `/dev/urandom`，Windows 使用系统 BCrypt；无系统随机源时报错，不降级使用时钟。示例 `examples/vm_stage1.lua` 与对应 `examples/vm_stage1.K.lua` 使用种子 `5122438661592891`。

混淆阶段及输出仍是实验性的，所有语法、所有环境和行为等价均未得到证明；请不要用于生产。

## 可选官方差分测试

项目构建不依赖官方工具。若本机已有官方 `luau-compile` 和对应 Luau 源码，可设置以下变量进行语法接受/拒绝对照：

```sh
LUAU_VM=/path/to/luau \
LUAU_COMPILE=/path/to/luau-compile \
LUAU_CONFORMANCE_DIR=/path/to/luau/tests/conformance \
LUAU_TEST_SOURCE_DIR=/path/to/luau/tests \
cargo test --offline -- --nocapture
```

`LUAU_VM` 启用安全自建程序及生成程序的实际执行对照，比较返回数量、值、尾部 nil、数字特殊值和 print 参数；未设置时跳过。其余官方解析对照测试在缺少对应变量时也会输出跳过提示；设置后若路径或工具不可用则测试失败。解析对照通过 `--null --only-parse` 比较解析结果，不执行输入，不比较 AST、报错详情、类型检查或编译期语义。`LUAU_COMPILE` 还启用固定种子的 1,000 项 token 变异测试；`LUAU_CONFORMANCE_DIR` 启用目录对照，以及打开上游 `DebugLuauWhileLocalSyntax` 的 `whilelocal.luau` 对照；`LUAU_TEST_SOURCE_DIR` 从该目录顶层 C++ 测试源提取原始字符串进行对照，测试不会把语料复制到仓库。

使用官方 Luau 0.745（提交 `2a3d8937c19c8fd9f7b72b6ec9068c62760e6588`）默认 flags 的一次对照结果：58 个 conformance 文件中双方均接受 55、均拒绝 3；7,173 个 C++ 原始字符串中双方均接受 4,567、均拒绝 2,606；两组接受/拒绝差异均为 0。所测样本有限，版本和 flags 改变也会影响结果，不能据此宣称覆盖所有 Luau/Roblox 语法。
