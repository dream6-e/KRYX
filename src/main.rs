// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
mod cli;
mod source;

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
        cli::Command::Input(paths) => match source::read(&paths.input) {
            Ok(source) => {
                eprintln!(
                    "已读取 {}（{} 字节）。混淆功能尚未实现；未生成 {}。",
                    paths.input.display(),
                    source.len(),
                    paths.output.display()
                );
                ExitCode::from(1)
            }
            Err(error) => {
                eprintln!("无法读取 {}：{error}", paths.input.display());
                ExitCode::from(1)
            }
        },
    }
}
