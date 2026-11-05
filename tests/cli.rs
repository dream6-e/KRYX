// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "kryx-test-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_kryx"))
}

#[test]
fn help_succeeds_and_invalid_invocation_fails() {
    let help = binary().arg("--help").output().unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8(help.stdout).unwrap().contains("基础框架"));
    assert!(!binary().output().unwrap().status.success());
    assert!(!binary()
        .args(["a.lua", "b.lua"])
        .output()
        .unwrap()
        .status
        .success());
}

#[test]
fn reading_input_does_not_modify_or_create_output() {
    let dir = TestDir::new();
    let input = dir.0.join("test.lua");
    let output = dir.0.join("test.K.lua");
    let contents = b"print('hi')\r\n\xff";
    fs::write(&input, contents).unwrap();

    let result = binary().arg(&input).output().unwrap();
    assert!(!result.status.success());
    let error = String::from_utf8(result.stderr).unwrap();
    assert!(error.contains("尚未实现"));
    assert_eq!(fs::read(&input).unwrap(), contents);
    assert!(!output.exists());
}

#[test]
fn existing_output_is_never_overwritten() {
    let dir = TestDir::new();
    let input = dir.0.join("test.lua");
    let output = dir.0.join("test.K.lua");
    fs::write(&input, b"return 1").unwrap();
    fs::write(&output, b"previous output").unwrap();

    assert!(!binary().arg(&input).output().unwrap().status.success());
    assert_eq!(fs::read(output).unwrap(), b"previous output");
}

#[test]
fn missing_or_directory_input_reports_an_error() {
    let dir = TestDir::new();
    for input in [dir.0.join("missing.lua"), dir.0.clone()] {
        let result = binary().arg(input).output().unwrap();
        assert!(!result.status.success());
        assert!(String::from_utf8(result.stderr)
            .unwrap()
            .contains("无法读取"));
    }
}

#[test]
fn check_mode_parses_without_running_or_writing() {
    let dir = TestDir::new();
    let input = dir.0.join("check.luau");
    let output = dir.0.join("check.K.lua");
    fs::write(&input, b"error('must not execute')").unwrap();
    let result = binary().args(["--check"]).arg(&input).output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!output.exists());
    fs::write(&input, b"local x =").unwrap();
    let result = binary().args(["--check"]).arg(&input).output().unwrap();
    assert!(!result.status.success());
    assert!(!output.exists());
}
