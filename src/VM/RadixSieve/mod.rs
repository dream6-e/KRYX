// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
mod detect;
mod convert;

pub use detect::LuaVersion;
pub use detect::detect_version;
pub use convert::apply_radix_sieve;
pub use apply_radix_sieve as apply;