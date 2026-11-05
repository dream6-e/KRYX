// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use std::fs;
use std::process::Command;

/// Set LUAU_COMPILE to an official luau-compile executable to enable this test.
/// Compilation only: none of the test programs are executed.
#[test]
fn compare_with_official_luau_compiler_when_available() {
    let Some(compiler) = std::env::var_os("LUAU_COMPILE") else {
        eprintln!("LUAU_COMPILE not set; differential test skipped");
        return;
    };
    let cases = [
        "local x = 0X1e+3; x += 2",
        "type T = {read x: number, [string]: boolean}",
        "local function f<T>(x: T): T return x end; return f<<number>>(1)",
        "local x = `nested {`inner {1}`} end`",
        "for _, part in workspace:GetChildren() do if part:IsA('Part') then part.Transparency += 1 else continue end end",
        "local x = if local v = game then v.Name else 'none'",
        "@native local function f(x: number): number return x end",
        "export local answer = 42",
        "return 2^3^4, -2^2",
        "local x = 1e+",
        "local x = 0b102",
        "local x = '\\xzz'",
        "local x = '\\u{}'",
        "local x = '\\256'",
        "local x = `\\xZZ`",
        "local x = `\\300`",
        "local x = 999999999999999999999999999999999999999999i",
        "local x = `{{x}}`",
        "local x = `{}`",
        "break",
        "continue",
        "local f = function() return ... end",
        "return 1; print(2)",
        "while true do break print(1) end",
        "1 = 2",
        "local x: = 3",
        "local x: (number, string) = nil",
        "local x: function = nil",
        "local x: A... = nil",
        "local x: ...number = nil",
        "type T = A | B & C",
        "local x = if true then 1",
        "local x = {a = }",
        "local x = function(,) end",
    ];
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "kryx-diff-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&dir).unwrap();
    let file = dir.join("case.luau");
    for case in cases {
        fs::write(&file, case).unwrap();
        let official = Command::new(&compiler)
            .arg("--null")
            .arg("--only-parse")
            .arg(&file)
            .output()
            .expect("failed to start LUAU_COMPILE");
        let ours = kryx::parser::parse(case.as_bytes());
        assert_eq!(
            ours.is_ok(),
            official.status.success(),
            "case: {case}\nours: {ours:?}\nofficial: {}",
            String::from_utf8_lossy(&official.stderr)
        );
    }
    fs::remove_dir_all(dir).unwrap();
}

/// Optionally compare an external directory of `.luau` files without executing them.
#[test]
fn compare_external_conformance_directory_when_requested() {
    let Some(dir) = std::env::var_os("LUAU_CONFORMANCE_DIR") else {
        eprintln!("LUAU_CONFORMANCE_DIR not set; corpus comparison skipped");
        return;
    };
    let compiler =
        std::env::var_os("LUAU_COMPILE").expect("set LUAU_COMPILE alongside LUAU_CONFORMANCE_DIR");
    let mut files: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "luau"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no .luau files found");
    let mut mismatches = Vec::new();
    let mut both_accept = 0;
    let mut both_reject = 0;
    for file in &files {
        let bytes = fs::read(file).unwrap();
        let official = Command::new(&compiler)
            .arg("--null")
            .arg("--only-parse")
            .arg(file)
            .output()
            .expect("failed to start LUAU_COMPILE");
        let ours = kryx::parser::parse(&bytes);
        match (official.status.success(), ours.is_ok()) {
            (true, true) => both_accept += 1,
            (false, false) => both_reject += 1,
            (official_ok, _) => mismatches.push(format!(
                "{}: official={official_ok}, ours={}",
                file.display(),
                ours.err()
                    .map_or_else(|| "accepted".to_owned(), |e| e.to_string())
            )),
        }
    }
    eprintln!(
        "{} files: both accept {both_accept}, both reject {both_reject}, mismatches {}",
        files.len(),
        mismatches.len()
    );
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}
