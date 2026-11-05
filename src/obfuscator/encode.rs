// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use super::compiler::{Constant, Program, OP_COUNT};
use super::{ObfuscationError, Result};

fn varint(mut n: u64, out: &mut Vec<u8>) {
    while n >= 128 {
        out.push((n as u8 & 127) | 128);
        n >>= 7;
    }
    out.push(n as u8);
}
fn number(n: usize, out: &mut Vec<u8>) -> Result<()> {
    let n = u64::try_from(n).map_err(|_| ObfuscationError("数据过大".into()))?;
    if n > 9_007_199_254_740_992 {
        return Err(ObfuscationError("数据超出 Luau 精确整数范围".into()));
    }
    varint(n, out);
    Ok(())
}
pub(super) fn serialize(program: &Program, mapping: &[u8; OP_COUNT]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    number(program.registers, &mut out)?;
    number(program.constants.len(), &mut out)?;
    for k in &program.constants {
        match k {
            Constant::Nil => varint(0, &mut out),
            Constant::Bool(false) => varint(1, &mut out),
            Constant::Bool(true) => varint(2, &mut out),
            Constant::Integer(n) => {
                varint(3, &mut out);
                varint(*n, &mut out);
            }
            Constant::String(s) => {
                varint(4, &mut out);
                number(s.len(), &mut out)?;
                out.extend(s);
            }
        }
    }
    number(program.code.len(), &mut out)?;
    for i in &program.code {
        varint(mapping[i.op as usize] as u64, &mut out);
        number(i.a, &mut out)?;
        number(i.b, &mut out)?;
        number(i.c, &mut out)?;
    }
    Ok(out)
}

/// Encode complete 4-byte groups with the sample's ASCII-85 style alphabet.
/// Padding is ignored by the length-delimited binary reader.
pub(super) fn encode85(bytes: &[u8]) -> String {
    let mut encoded = String::new();
    for chunk in bytes.chunks(4) {
        let mut buf = [0; 4];
        buf[..chunk.len()].copy_from_slice(chunk);
        let mut value = u32::from_be_bytes(buf);
        if value == 0 {
            encoded.push('z');
            continue;
        }
        let mut group = [0u8; 5];
        for i in (0..5).rev() {
            group[i] = (value % 85) as u8 + 33;
            value /= 85;
        }
        encoded.push_str(std::str::from_utf8(&group).unwrap());
    }
    encoded
}
