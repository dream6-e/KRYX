// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LuaVersion {
    Lua,
    Luau,
}

pub fn detect_version(code: &str) -> LuaVersion {
    if code.contains("--!strict") || code.contains("::") || code.contains("type ") {
        LuaVersion::Luau
    } else {
        LuaVersion::Lua
    }
}