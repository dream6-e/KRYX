// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use std::io;
use std::path::Path;

/// Read input without changing bytes, encoding, line endings, or the input file.
pub fn read(path: &Path) -> io::Result<Vec<u8>> {
    std::fs::read(path)
}
