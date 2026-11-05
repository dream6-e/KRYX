// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
//! Experimental register-VM generator for an explicitly limited Luau subset.
mod compiler;
mod emitter;
mod encode;
pub mod seed;

use std::fmt;

#[derive(Debug)]
pub struct ObfuscationError(pub String);
impl fmt::Display for ObfuscationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ObfuscationError {}

type Result<T> = std::result::Result<T, ObfuscationError>;

/// Generate a deterministic output for a given 16-digit decimal seed.
/// Unsupported constructs return an error; no source code is ever executed here.
pub fn generate(source: &[u8], seed: u64) -> Result<String> {
    if !(1_000_000_000_000_000..=9_999_999_999_999_999).contains(&seed) {
        return Err(ObfuscationError("种子必须是 16 位十进制整数".into()));
    }
    let tree = crate::parser::parse(source).map_err(|e| ObfuscationError(e.to_string()))?;
    let program = compiler::compile(&tree)?;
    let mut rng = seed::Random::new(seed);
    let mapping = emitter::opcode_mapping(&mut rng);
    let bytes = encode::serialize(&program, &mapping)?;
    Ok(emitter::emit(&program, &bytes, &mapping, &mut rng))
}
