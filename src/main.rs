// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
#![allow(warnings)]

/*
 (c)KRYVEX Ob
 BY ssssss85
 Virtualization obfuscation
*/

use std::io::Write;
use std::process;
use std::thread;
use std::time::Instant;

use kryvex_ob::compiler::codegen;
use kryvex_ob::compiler::dump;
use kryvex_ob::BytecodeCompiler::virtualizer::deserializer::Deserializer;
use kryvex_ob::VM::VM_Backend::Context::VmContext;
use kryvex_ob::VM::VM_Backend::Serializer::Serializer;
use kryvex_ob::VM::VM_Backend::Generator::Generator;
use kryvex_ob::compressor::Compressor;
use kryvex_ob::VM::RadixSieve;
use kryvex_ob::packer;
use kryvex_ob::parenwrap;

fn main() {
    let start_time = Instant::now();
    let args: Vec<String> = std::env::args().collect();
    let source_code;
    let mut current_file = String::new();

    if args.len() >= 2 {
        let mut input_path = args[1].clone();
        
        if input_path == "-h" || input_path == "--help" {
            eprintln!("Usage: cargo run --release -- <input_file.lua>");
            return;
        }

        if !input_path.ends_with(".lua") {
            input_path.push_str(".lua");
        }
        current_file = input_path.clone();
        source_code = match std::fs::read_to_string(&input_path) {
            Ok(content) => content,
            Err(e) => {
                eprintln!("\x1b[1;31mKRYVEX: \x1b[0m 无法读取输入文件: {:?}", e);
                return;
            }
        };
    } else {
        let mut loop_source = String::new();
        print!("KRYVEX: obfuscation\n");
        loop {
            print!("\x1b[1;33m请输入目标文件: \x1b[0m");
            std::io::stdout().flush().unwrap();
            
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            
            let mut input_path = input.trim().to_string();
            if input_path.is_empty() {
                continue;
            }

            if !input_path.ends_with(".lua") {
                input_path.push_str(".lua");
            }

            match std::fs::read_to_string(&input_path) {
                Ok(content) => {
                    current_file = input_path;
                    loop_source = content;
                    break;
                }
                Err(_) => {
                    println!("\x1b[1;31m文件不存在或无法读取，请重新输入！\x1b[0m");
                }
            }
        }
        source_code = loop_source;
    }

    match codegen::compile(source_code.as_bytes(), &format!("@{}", current_file)) {
        Ok(proto) => {
            let bytes = dump::dump(&proto, true);

            let _ = std::fs::create_dir_all("process");

            if let Ok(entries) = std::fs::read_dir("process") {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        let _ = std::fs::remove_file(path);
                    } else if path.is_dir() {
                        let _ = std::fs::remove_dir_all(path);
                    }
                }
            }
            
            let bytes_clone = bytes.clone();
            let h1 = thread::spawn(move || {
                let _ = std::fs::write("process/luac out.bin", bytes_clone);
            });

            let mut deserializer = Deserializer::new(bytes);
            let decoded_chunk = deserializer.decode_file();
            let vm_ctx = VmContext::new();
            
            let private_payload = Serializer::serialize(&decoded_chunk, &vm_ctx);
            
            let vm_generator = Generator::new(vm_ctx);
            let obfuscated_vm = vm_generator.build(&private_payload);

            let obfuscated_vm_clone = obfuscated_vm.clone();
            let h2 = thread::spawn(move || {
                let _ = std::fs::write("process/process1.lua", obfuscated_vm_clone);
            });
            let compressed_vm = match Compressor::compress(&obfuscated_vm) {
                Ok(code) => code,
                Err(e) => {
                    eprintln!("{}", e);
                    process::exit(1);
                }
            };

            let compressed_vm_clone = compressed_vm.clone();
            let h3 = thread::spawn(move || {
                let _ = std::fs::write("process/process2.lua", compressed_vm_clone);
            });

            let processed_vm = match RadixSieve::apply(&compressed_vm, None) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("\x1b[1;31mKRYVEX: \x1b[0m 数字转换失败: {}", e);
                    process::exit(1);
                }
            };
            let _ = std::fs::write("process/process3.lua", &processed_vm);

            let final_code = if args.contains(&"MB".to_string()) {
                let packed_vm = packer::pack_lua(&processed_vm);
                let compressed_packed_vm = match Compressor::compress(&packed_vm) {
                    Ok(code) => code,
                    Err(e) => {
                        eprintln!("{}", e);
                        process::exit(1);
                    }
                };
                compressed_packed_vm
            } else {
                processed_vm
            };

            let final_code = parenwrap::wrap_misc(&final_code);

            // Luau 首要支持：0b 二进制与带下划线字面量 Luau 均原生支持，无需改动。
            // 仅对 Lua 5.1 不支持的带下划线十六进制（如 0X_9_8、0x_a_3）做清理，
            // 避免在 lua5.1 下出现 'malformed number' 语法错误。
            let final_code = clean_hex_literals(&final_code);

            let mut file = match std::fs::File::create("obfuscated.lua") {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("\x1b[1;31mKRYVEX: \x1b[0m 无法创建最终文件: {:?}", e);
                    return;
                }
            };
            if let Err(e) = file.write_all(final_code.as_bytes()) {
                eprintln!("\x1b[1;31mKRYVEX: \x1b[0m 写入最终文件失败: {:?}", e);
                return;
            }

            let _ = h1.join();
            let _ = h2.join();
            let _ = h3.join();
            println!("\x1b[1;33mKRYVEX: \x1b[0m 混淆已保存至 \x1b[1m\x1b[4mobfuscated.lua\x1b[0m");
            println!("\x1b[1;33mKRYVEX: \x1b[0m {:?}", start_time.elapsed());
        },
        Err(e) => {
            eprintln!("{}", e);
            process::exit(1);
        }
    }
}

/// 清理 Lua 5.1 不支持的带下划线十六进制字面量（如 `0X_9_8`、`0x_a_3`、`0x100_`）。
/// Luau 首要支持：0b 二进制与带下划线字面量 Luau 均原生支持，此处不做二进制转换。
/// Lua 5.1 词法分析器不接受数字字面量中的 `_`；将其清理为合法的 `0x` 十六进制格式。
fn clean_hex_literals(code: &str) -> String {
    let chars: Vec<char> = code.chars().collect();
    let mut out = String::with_capacity(chars.len());
    let mut i = 0;
    while i < chars.len() {
        // 检测 0x / 0X 前缀（不再处理 0b / 0B，Luau 原生支持二进制字面量）
        if i + 1 < chars.len() && chars[i] == '0' && (chars[i + 1] == 'x' || chars[i + 1] == 'X') {
            let mut j = i + 2;
            // 读取十六进制数字和下划线
            while j < chars.len() {
                let c = chars[j];
                if c.is_ascii_hexdigit() || c == '_' {
                    j += 1;
                } else {
                    break;
                }
            }
            if j > i + 2 {
                // 提取并去除下划线
                let hex_part: String = chars[i + 2..j].iter().filter(|&c| *c != '_').collect();
                if !hex_part.is_empty() {
                    out.push_str("0x");
                    out.push_str(&hex_part.to_lowercase());
                }
                i = j;
            } else {
                out.push(chars[i]);
                i += 1;
            }
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}
