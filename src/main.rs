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
            // sample2 形态整形：紧接着生成器做，此时标识符还是生成器登记的原始长名，
            // 才认得哪些是「自己造的名字」可以搬成槽位/方法。
            // 1) shell 的共享状态 → 环境数字键槽位 `u[0x..]`
            // 2) depth-0 的局部函数 → 大表方法 `v:名字(...)`
            let mut reshape_rng = kryvex_ob::VM::VM_Backend::Generator::GenRng::new(0);
            let raw_vm = vm_generator.build(&private_payload);
            if std::env::var("KRYX_DEBUG_SHAPE_RAW").is_ok() {
                let _ = std::fs::write("process/raw.lua", &raw_vm);
            }
            let (obfuscated_vm, shape_stats) =
                kryvex_ob::VM::Reshape::apply(&raw_vm, &mut reshape_rng);
            if std::env::var("KRYX_DEBUG_SHAPED").is_ok() {
                let _ = std::fs::write("process/shaped.lua", &obfuscated_vm);
            }

            let obfuscated_vm_clone = obfuscated_vm.clone();
            let h2 = thread::spawn(move || {
                let _ = std::fs::write("process/process1.lua", obfuscated_vm_clone);
            });
            // 把所有「生成器造出来的」标识符统一压成 1~2 字符（sample2 全文件都是
            // 1~2 字符名）。固定名（execute/chunk/env/op/inst_A/getgenv/... 这些
            // 模板里写死的未登记标识符）不参与，映射单射 ⇒ 语义不变。
            let obfuscated_vm = kryvex_ob::VM::Names::shrink_once(&obfuscated_vm);
            let _ = shape_stats;

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

            // sample2 形态收尾：入口名压成单字母（`:J()` 形态）。
            // 标识符的 1~2 字符化在生成器阶段就已经完成（Names::shrink 紧跟整形），
            // 这里只处理 `}):X()(...)` 的入口名。
            // 体积优化：同一函数内重复出现的数字字面量抽成局部变量（用户 2026-11-18）。
            let seq_min = std::env::var("KRYX_SEQ_MIN")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(3);
            // 体积优化：同一作用域里反复出现的 `nil` / `getgenv` 抽成局部变量（用户 2026-11-18）。
            // 必须在 hoist_repeated_numbers 之前：常量先落地，数字再去复用。
            let const_min = std::env::var("KRYX_CONST_MIN")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(3);
            let (final_code, hoisted_consts) =
                kryvex_ob::hoist::hoist_constants(&final_code, const_min);
            if std::env::var("KRYX_DEBUG_SEQ").is_ok() {
                eprintln!("[hoist] constants = {}", hoisted_consts);
            }
            let (final_code, hoisted_numbers) = kryvex_ob::seq::hoist_repeated_numbers(&final_code, seq_min);
            if std::env::var("KRYX_DEBUG_SEQ").is_ok() {
                eprintln!("[seq] hoisted numbers = {}", hoisted_numbers);
            }
            let final_code = kryvex_ob::VM::Names::promote_entry(&final_code);
            let final_code = parenwrap::wrap_misc(&final_code);

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