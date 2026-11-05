# KRYX

纯 Rust、无外部依赖的 Luau 混淆器基础框架。当前没有混淆步骤，不生成或覆盖 `.K.lua` 文件。

## 实验性解析器

```sh
cargo run -- --check test.lua    # 只读取和解析，不执行、不写文件
cargo test --offline             # 单元及集成测试
cargo run -- test.lua            # 混淆功能尚未实现，返回非零退出码
```

`--check` 构建 AST，报告首个词法/语法错误的字节偏移对应的行列（列按字节计算）。库接口为 `kryx::parser::parse(&[u8])`：结果保留原始字节、含空白和注释的完整 token 序列、带半开字节范围和子节点的语法树。表达式树记录运算符和结合优先级，赋值节点区分目标和值。解析器包括常见 Luau 控制流、函数、表、类型、泛型、插值字符串和 Roblox API 调用语法；Roblox API 在语法上是普通标识符、索引和调用，不做 API/类型检查。

**这不是完整 Luau 语法实现，也不是官方编译器的替代品。** 目前只做实验性静态解析，没有作用域/类型检查、Luau 版本/特性开关建模或错误恢复；某些错误程序可能被接受，某些有效程序可能被拒绝。例如尚未校验属性名称（`@weird` 会被接受，但官方编译器会拒绝）；为限制递归栈使用，解析嵌套深度上限为 48。`--check` 的成功不能证明源码合法或能运行，不能据此生成混淆输出。项目尚无压缩、随机种子、代码生成或混淆能力。

## 可选官方编译器对照测试

如果本机已有官方 `luau-compile`，可启用手写合法/非法用例对照；也可提供官方 Luau 源码树的 `tests/conformance` 路径进行额外的语料对照：

```sh
LUAU_COMPILE=/path/to/luau-compile cargo test --offline
LUAU_COMPILE=/path/to/luau-compile LUAU_CONFORMANCE_DIR=/path/to/luau/tests/conformance cargo test --offline --test differential -- --nocapture
```

环境变量未设置时，相应对照测试会跳过；不影响纯 Rust 项目构建。官方编译器仅用于测试时语法编译，不会被项目调用或作为依赖。语料结果取决于官方版本和功能开关，不能证明对全部语法的覆盖。

默认未来输出路径仍为同目录 `test.K.lua`；以 `-` 开头的文件名可用 `cargo run -- --check -- -file.lua` 或 `cargo run -- -- -file.lua` 指定。
