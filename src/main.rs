// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
mod cli;
mod source;

use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    let command = match cli::parse(std::env::args_os().skip(1)) {
        Ok(command) => command,
        Err(message) => {
            eprintln!("{message}\n\n{}", cli::usage());
            return ExitCode::from(2);
        }
    };

    match command {
        cli::Command::Help => {
            println!("{}", cli::usage());
            ExitCode::SUCCESS
        }
        cli::Command::Check(paths) => {
            match source::read(&paths.input) {
                Ok(source) => {
                    match kryx::parser::parse(&source) {
                        Ok(tree) => {
                            println!("解析完成：{}（{} 个顶层语句）。实验性解析器，不等同于官方语法验证。", paths.input.display(), tree.root.children.len());
                            ExitCode::SUCCESS
                        }
                        Err(error) => {
                            eprintln!("{}:{error}", paths.input.display());
                            ExitCode::from(1)
                        }
                    }
                }
                Err(error) => {
                    eprintln!("无法读取 {}：{error}", paths.input.display());
                    ExitCode::from(1)
                }
            }
        }
        cli::Command::Input(paths, seed) => {
            let source = match source::read(&paths.input) {
                Ok(source) => source,
                Err(error) => {
                    eprintln!("无法读取 {}：{error}", paths.input.display());
                    return ExitCode::from(1);
                }
            };
            let seed = match seed
                .map(Ok)
                .unwrap_or_else(kryx::obfuscator::seed::generate)
            {
                Ok(seed) => seed,
                Err(error) => {
                    eprintln!("{error}");
                    return ExitCode::from(1);
                }
            };
            let output = match kryx::obfuscator::generate(&source, seed) {
                Ok(output) => output,
                Err(error) => {
                    eprintln!("混淆失败：{error}");
                    return ExitCode::from(1);
                }
            };
            let mut file = match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&paths.output)
            {
                Ok(file) => file,
                Err(error) => {
                    eprintln!("无法创建 {}：{error}", paths.output.display());
                    return ExitCode::from(1);
                }
            };
            if let Err(error) = file.write_all(output.as_bytes()) {
                drop(file);
                let _ = std::fs::remove_file(&paths.output);
                eprintln!("写入失败：{error}");
                return ExitCode::from(1);
            }
            println!("已生成 {}（种子：{seed}）", paths.output.display());
            ExitCode::SUCCESS
        }
    }
}
