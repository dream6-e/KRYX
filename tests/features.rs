// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use kryx::parser::{parse, parse_with_options, ParseOptions};
use std::fs;
use std::process::Command;

#[test]
fn optional_while_local_scopes_binding_to_loop_body() {
    let options = ParseOptions { while_local: true };
    let good = [
        "while local x: number = next() do x += 1 end",
        "while const x = next() do print(x) end; x=1",
        "while const do break end",
    ];
    for source in good {
        assert!(
            parse_with_options(source.as_bytes(), options).is_ok(),
            "{source}"
        );
    }
    let bad = ["while local x=1 do x=2 end", "while const x=1 do x=2 end"];
    assert!(parse_with_options(bad[0].as_bytes(), options).is_ok());
    assert!(parse_with_options(bad[1].as_bytes(), options).is_err());
    assert!(parse(good[0].as_bytes()).is_err());
}

#[test]
fn optional_while_local_matches_upstream_flag_when_available() {
    let (Some(compiler), Some(dir)) = (
        std::env::var_os("LUAU_COMPILE"),
        std::env::var_os("LUAU_CONFORMANCE_DIR"),
    ) else {
        eprintln!("LUAU_COMPILE/LUAU_CONFORMANCE_DIR not set; optional feature corpus skipped");
        return;
    };
    let path = std::path::PathBuf::from(dir).join("whilelocal.luau");
    let input = fs::read(&path).expect("missing whilelocal.luau");
    let reference = Command::new(compiler)
        .args([
            "--null",
            "--only-parse",
            "--fflags=DebugLuauWhileLocalSyntax=true",
        ])
        .arg(path)
        .output()
        .unwrap();
    assert!(
        reference.status.success(),
        "{}",
        String::from_utf8_lossy(&reference.stderr)
    );
    assert!(parse_with_options(&input, ParseOptions { while_local: true }).is_ok());
}
