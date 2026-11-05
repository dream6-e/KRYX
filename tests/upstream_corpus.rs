// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Extract C++ raw-string contents. The upstream source remains external to KRYX.
fn raw_strings(source: &str) -> Vec<&str> {
    let bytes = source.as_bytes();
    let mut result = Vec::new();
    let mut pos = 0;
    while pos + 2 < bytes.len() {
        if bytes[pos] != b'R' || bytes[pos + 1] != b'"' {
            pos += 1;
            continue;
        }
        let start = pos + 2;
        let mut open = start;
        while open < bytes.len()
            && open - start <= 16
            && bytes[open] != b'('
            && !matches!(bytes[open], b' ' | b'\\' | b'\n' | b'\r' | b'\t')
        {
            open += 1;
        }
        if open == bytes.len() || bytes[open] != b'(' || open - start > 16 {
            pos += 2;
            continue;
        }
        let mut close = Vec::with_capacity(open - start + 2);
        close.push(b')');
        close.extend_from_slice(&bytes[start..open]);
        close.push(b'"');
        let content = open + 1;
        let Some(end) = bytes[content..]
            .windows(close.len())
            .position(|w| w == close)
            .map(|i| content + i)
        else {
            break;
        };
        if end - content <= 80_000 {
            result.push(&source[content..end]);
        }
        pos = end + close.len();
    }
    result
}

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn compare_upstream_raw_strings_when_requested() {
    let Some(directory) = std::env::var_os("LUAU_TEST_SOURCE_DIR") else {
        eprintln!("LUAU_TEST_SOURCE_DIR not set; upstream source corpus skipped");
        return;
    };
    let compiler =
        std::env::var_os("LUAU_COMPILE").expect("set LUAU_COMPILE alongside LUAU_TEST_SOURCE_DIR");
    let mut files: Vec<_> = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".cpp"))
        })
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no upstream C++ test source files found");
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let name = format!("kryx-upstream-{}-{stamp}", std::process::id());
    let tmp = TempDir(std::env::temp_dir().join(name));
    fs::create_dir(&tmp.0).unwrap();
    let case = tmp.0.join("case.luau");
    let (mut total, mut accepted, mut rejected) = (0usize, 0usize, 0usize);
    let mut errors = Vec::new();
    for file in files {
        let text = fs::read_to_string(&file).unwrap();
        for (index, source) in raw_strings(&text).into_iter().enumerate() {
            fs::write(&case, source).unwrap();
            let reference = Command::new(&compiler)
                .arg("--null")
                .arg("--only-parse")
                .arg(&case)
                .output()
                .expect("failed to start LUAU_COMPILE");
            let ours = kryx::parser::parse(source.as_bytes());
            total += 1;
            match (reference.status.success(), ours.is_ok()) {
                (true, true) => accepted += 1,
                (false, false) => rejected += 1,
                (official_ok, _) => {
                    if errors.len() < 20 {
                        errors.push(format!(
                            "{} raw #{index}: official={official_ok}, ours={}, official error={}",
                            file.display(),
                            ours.err()
                                .map_or_else(|| "accepted".to_owned(), |e| e.to_string()),
                            String::from_utf8_lossy(&reference.stderr)
                                .lines()
                                .next()
                                .unwrap_or("")
                        ));
                    }
                }
            }
        }
    }
    assert!(total > 0, "no raw strings found in upstream source");
    eprintln!(
        "{total} snippets: both accept {accepted}, both reject {rejected}, mismatches {}",
        total - accepted - rejected
    );
    assert_eq!(total - accepted - rejected, 0, "{}", errors.join("\n"));
}
