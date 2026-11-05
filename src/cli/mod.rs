// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use std::ffi::OsString;
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq, Eq)]
pub struct Paths {
    pub input: PathBuf,
    pub output: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Help,
    Input(Paths),
}

pub fn usage() -> &'static str {
    "用法：cargo run -- <输入文件>\n       cargo run -- --help\n当前仅提供基础框架；不会生成混淆文件。"
}

pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Command, &'static str> {
    let mut args = args.into_iter();
    let first = args.next().ok_or("缺少输入文件")?;
    if first == "--help" || first == "-h" {
        return if args.next().is_none() {
            Ok(Command::Help)
        } else {
            Err("帮助选项不能与其他参数一起使用")
        };
    }

    let input = if first == "--" {
        args.next().ok_or("缺少输入文件")?
    } else {
        if first.to_string_lossy().starts_with('-') {
            return Err("未知选项；以 - 开头的文件名请放在 -- 之后");
        }
        first
    };
    if args.next().is_some() {
        return Err("只能指定一个输入文件");
    }

    let input = PathBuf::from(input);
    let output = output_path(&input).ok_or("输入路径必须包含文件名")?;
    Ok(Command::Input(Paths { input, output }))
}

fn output_path(input: &Path) -> Option<PathBuf> {
    let mut name = input.file_stem()?.to_os_string();
    name.push(".K.lua");
    Some(input.with_file_name(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_strings(args: &[&str]) -> Result<Command, &'static str> {
        parse(args.iter().map(OsString::from))
    }

    #[test]
    fn computes_default_output_in_same_directory() {
        assert_eq!(
            parse_strings(&["dir/test.lua"]),
            Ok(Command::Input(Paths {
                input: "dir/test.lua".into(),
                output: "dir/test.K.lua".into(),
            }))
        );
        assert_eq!(
            parse_strings(&["script.luau"]),
            Ok(Command::Input(Paths {
                input: "script.luau".into(),
                output: "script.K.lua".into(),
            }))
        );
    }

    #[test]
    fn handles_help_and_invalid_arguments() {
        assert_eq!(parse_strings(&["--help"]), Ok(Command::Help));
        assert_eq!(parse_strings(&["-h"]), Ok(Command::Help));
        assert!(parse_strings(&[]).is_err());
        assert!(parse_strings(&["--help", "extra"]).is_err());
        assert!(parse_strings(&["a.lua", "b.lua"]).is_err());
        assert!(parse_strings(&["--unknown"]).is_err());
        assert!(parse_strings(&["--"]).is_err());
    }

    #[test]
    fn accepts_dash_prefixed_filename_after_separator() {
        assert_eq!(
            parse_strings(&["--", "-input.lua"]),
            Ok(Command::Input(Paths {
                input: "-input.lua".into(),
                output: "-input.K.lua".into(),
            }))
        );
    }

    #[test]
    fn refuses_paths_without_a_filename() {
        assert!(parse_strings(&["/"]).is_err());
        assert!(parse_strings(&[""]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn supports_non_utf8_paths_without_lossy_conversion() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        let input = OsString::from_vec(b"\xff.lua".to_vec());
        let Command::Input(paths) = parse([input]).unwrap() else {
            panic!("expected input command");
        };
        assert_eq!(paths.output.as_os_str().as_bytes(), b"\xff.K.lua");
    }
}
