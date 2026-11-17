// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use super::*;

// 常量惰性解密缓存上限：达到后整体清空明文缓存，强制下次重新解密（Phase 1 需求）
const CONST_CACHE_LIMIT: i64 = 32;
impl Generator {
    pub fn new(ctx: VmContext) -> Self { Self { ctx } }

    pub fn build(&self, payload: &[u8]) -> String {
        let mut rng = GenRng::new(self.ctx.seed);
        let var_l = rng.name();
        
        let key_seed_var = rng.name();
        let at = AntiTamper::generate_split(true, &key_seed_var);
        
        let mut used_ops = HashSet::new();
        { let mut scan_reader = PayloadReader { data: payload, pos: 0 }; scan_used_opcodes(&mut scan_reader, &mut used_ops); }

        let mut setglobal_targets: HashSet<Vec<u8>> = HashSet::new();
        let setglobal_op = self.ctx.opcode_map[7];
        let getglobal_op = self.ctx.opcode_map[5];
        let getglobalstr_op = self.ctx.opcode_map[56];
        let mut inverse_opcode_map = [0u8; 90];
        for i in 0..90 { inverse_opcode_map[self.ctx.opcode_map[i] as usize] = i as u8; }
        let builtin_slot_perm = Opcodes::builtins::slot_permutation(self.ctx.seed);
        { let mut sg_reader = PayloadReader { data: payload, pos: 0 }; scan_setglobal_targets(&mut sg_reader, &mut setglobal_targets, setglobal_op); }
        let setglobalstr_op = self.ctx.opcode_map[57];
        let mut global_refcounts: std::collections::HashMap<Vec<u8>, u32> = std::collections::HashMap::new();
        { let mut gr_reader = PayloadReader { data: payload, pos: 0 }; scan_global_refs(&mut gr_reader, &mut global_refcounts, [getglobal_op, getglobalstr_op, setglobal_op, setglobalstr_op]); }
        let mut global_ctx = GlobalSlotCtx { refcounts: global_refcounts, by_name: std::collections::HashMap::new(), used_slots: std::collections::HashSet::new(), getglobal_op, getglobalstr_op, setglobal_op, setglobalstr_op };

        let mut mapped_opcodes: [Vec<u32>; Opcodes::builtins::TOTAL_OPCODES] = std::array::from_fn(|_| Vec::new());
        let mut transpile_map: [Vec<u32>; 90] = std::array::from_fn(|_| Vec::new());
        {
            let mut map_rng = StdRng::seed_from_u64(self.ctx.seed);
            let mut used = std::collections::HashSet::new();
            for i in 0..90 {
                let shuffled_val = self.ctx.opcode_map[i];
                let count = if used_ops.contains(&shuffled_val) { map_rng.random_range(3..=6) } else { 1 };
                for _ in 0..count {
                    loop {
                        let val = map_rng.random_range(80000..99999);
                        if used.insert(val) { mapped_opcodes[i].push(val); transpile_map[shuffled_val as usize].push(val); break; }
                    }
                }
            }
            for i in 90..Opcodes::builtins::TOTAL_OPCODES {
                let count = map_rng.random_range(3..=6);
                for _ in 0..count {
                    loop {
                        let val = map_rng.random_range(80000..99999);
                        if used.insert(val) { mapped_opcodes[i].push(val); break; }
                    }
                }
            }
        }

        let mut strings = Vec::new(); let mut numbers = Vec::new(); let mut rewritten_chunks = Vec::new();
        let mut reader = PayloadReader { data: payload, pos: 0 };
        let mut rewrite_rng = StdRng::seed_from_u64(self.ctx.seed + 1);
        rewrite_chunk(&mut reader, &mut rewritten_chunks, &mut strings, &mut numbers, &transpile_map, &mapped_opcodes, &setglobal_targets, &mut global_ctx, &inverse_opcode_map, &builtin_slot_perm, &mut rewrite_rng);

        let mut builtin_pool_indices: Vec<usize> = Vec::with_capacity(Opcodes::builtins::BUILTIN_NAMES.len());
        for name in Opcodes::builtins::BUILTIN_NAMES.iter() {
            let nb = name.as_bytes().to_vec();
            let pos = strings.iter().position(|x| x == &nb).unwrap_or_else(|| { strings.push(nb); strings.len() - 1 });
            builtin_pool_indices.push(pos);
        }
        // Phase 3：槽位化全局名同样强制进池（仅被启动期解密一次，密文条目本身无任何区分标记）
        let mut global_boot: Vec<(usize, Vec<u64>)> = Vec::with_capacity(global_ctx.by_name.len()); // (raw pool 索引, 别名槽位)
        {
            let mut v: Vec<(&Vec<u8>, &GlobalSlotInfo)> = global_ctx.by_name.iter().collect();
            v.sort_by(|a, b| a.0.cmp(b.0));
            for (name, info) in v {
                let nb = name.clone();
                let pos = strings.iter().position(|x| x == &nb).unwrap_or_else(|| { strings.push(nb.clone()); strings.len() - 1 });
                global_boot.push((pos, info.aliases.clone()));
            }
        }
        // Phase 3-2：假槽（decoy）——与真实条目形态完全一致的启动注册代码（垃圾名字、
        // 随机 30 位槽位、getter/setter 闭包），槽位不被字节码引用、数字池混入死条目，
        // 破解者无法区分真假条目，频次/引用分析被打乱。
        // D = max(4, 真实条目数 + 2) + 随机 0~2，封顶 16。
        let mut decoy_entries: Vec<(usize, Vec<u64>)> = Vec::new();
        {
            let mut used_slots: std::collections::HashSet<u64> = std::collections::HashSet::new();
            for (_, aliases) in &global_boot { for a in aliases { used_slots.insert(*a); } }
            let real_n = global_boot.len();
            let decoy_count = (real_n.max(2) + 2 + rng.range(0, 3)).max(4).min(16);
            let mut used_names: std::collections::HashSet<Vec<u8>> = strings.iter().cloned().collect();
            for n in Opcodes::builtins::BUILTIN_NAMES { used_names.insert(n.as_bytes().to_vec()); }
            for _ in 0..decoy_count {
                // 假名：形态合法的标识符乱码
                let name_bytes = loop {
                    let len = rng.range(5, 12);
                    let mut b = Vec::with_capacity(len);
                    for i in 0..len {
                        let cls = rng.range(0, 3);
                        let ch = if i == 0 || cls == 0 {
                            b'a' + rng.range(0, 26) as u8
                        } else if cls == 1 {
                            b'A' + rng.range(0, 26) as u8
                        } else {
                            b'0' + rng.range(0, 10) as u8
                        };
                        b.push(ch);
                    }
                    if used_names.insert(b.clone()) { break b; }
                };
                // 假槽位：同 30 位空间，唯一；以 f64 位模式写入数字池（死条目）
                let slot = loop {
                    let v = 0x4000_0000 + rng.range(0, 0x4000_0000) as u64;
                    if used_slots.insert(v) { numbers.push((v as f64).to_bits()); break v; }
                };
                let pos = strings.len();
                strings.push(name_bytes);
                decoy_entries.push((pos, vec![slot]));
            }
        }

        // 最外层 return ({ ... }) 壳：全部内建函数作为壳字段一次性解析，
        // wai 函数体只通过壳引用访问内建函数，不直接出现 math.floor 等全局引用。
        // 环境探测（getgenv/getfenv/_ENV/_G）按约定保留原样。
        let var_shell = rng.name();
        let k_sel = rng.name();
        let k_floor = rng.name();
        let k_random = rng.name();
        let k_char = rng.name();
        let k_byte = rng.name();
        let k_sub = rng.name();
        let k_concat = rng.name();
        let k_unpack = rng.name();
        let k_pcall = rng.name();
        let k_setmt = rng.name();
        let k_type = rng.name();
        let k_pairs = rng.name();
        let k_bx = rng.name();
        let k_band = rng.name();
        let k_bor = rng.name();
        let k_lshift = rng.name();
        let k_rshift = rng.name();
        let k_bnot = rng.name();

        let chacha_key: [u32; 8] = std::array::from_fn(|_| rng.next());
        let chacha_salt: u32 = rng.next();

        let mut pool_bytes = Vec::new();
        pool_bytes.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        for (idx, s) in strings.iter().enumerate() {
            let enc_s = chacha8_xor(&chacha_key, chacha_salt, idx as u32, 0, s);
            write_string(&mut pool_bytes, &enc_s);
        }
        pool_bytes.extend_from_slice(&(numbers.len() as u32).to_le_bytes());
        for (idx, n) in numbers.iter().enumerate() {
            let enc_n_bytes = chacha8_xor(&chacha_key, chacha_salt, idx as u32, 1, &n.to_le_bytes());
            pool_bytes.extend_from_slice(&enc_n_bytes);
        }
        
        let mut combined_payload = Vec::new();
        let (mut k1, mut k2, mut k3, mut k4) = ((rng.next() & 0xFF) as u8, (rng.next() & 0xFF) as u8, (rng.next() & 0xFF) as u8, (rng.next() & 0xFF) as u8);
        combined_payload.push(k1); combined_payload.push(k2); combined_payload.push(k3); combined_payload.push(k4);
        
        for b in pool_bytes.iter_mut() {
            let orig = *b;
            *b = orig ^ k1; *b = b.wrapping_sub(k2); *b = b.rotate_left((k3 % 8) as u32); *b = *b ^ k4; *b = b.wrapping_add(0x42);
            k1 = k1.wrapping_add(orig).rotate_left(1).wrapping_add(0x1B);
            k2 = k2.wrapping_mul(3).wrapping_add(*b).rotate_right(2);
            k3 = k3 ^ k1.wrapping_sub(k4);
            k4 = k4.wrapping_add(k2).rotate_left(3);
        }
        combined_payload.extend(pool_bytes); combined_payload.extend(rewritten_chunks);
        
        let key_kryvex = String::from("x1"); let p_out: Vec<String> = (0..6).map(|_| rng.name()).collect();
        let var_s = rng.name(); let fn_N_ = rng.name(); let var_L = rng.name(); let var_get_count = rng.name();
        let hex_select_idx = format!("{:#x}", rng.range(10, 255));
        let var_state_flag = rng.name();
        let wai = rng.name();
        let mut header_block = String::new();
        header_block.push_str(&format!("return ({{ {} = function({},aggv,agv,agv,agv,aggv,agv,agv,aggv,aggv,aggv,agggv,agggv,agggv,agggv,aggv,{},{},{},{}, ...)\n", wai, var_shell, p_out[0], p_out[1], p_out[2], p_out[3]));
        header_block.push_str(&format!("local {} = {{}}; local {} = false; ", var_s, var_state_flag));
        header_block.push_str(&format!("local {} = function(q, s, M, C) s[{}] = M; end; ", fn_N_, hex_select_idx));
        header_block.push_str(&format!("{}(nil, {}, {}.{}, nil); ", fn_N_, var_s, var_shell, k_sel));
        
        let keys = CipherKeys { 
            grp1: rng.range(0x10, 0x7F) as u64, 
            grp2: rng.range(0x10, 0x7F) as u64, 
            key_bx: rng.range(0x10, 0x7F) as u64, 
            key_ba: rng.range(0x10, 0x7F) as u64, 
            key_add: rng.range(0x10, 0x7F) as u64, 
            key_bs: rng.range(0x10, 0x7F) as u64, 
            key_ba2: rng.range(0x10, 0x7F) as u64, 
            key_bs2: rng.range(0x10, 0x7F) as u64, 
            tbl_p: rng.name() 
        };

        let fn_bx = rng.name();
        let fn_ba = rng.name();
        let fn_bs = rng.name();
        let mut block_p_def = String::new();
        block_p_def.push_str(&format!("local {}={}.{}; local {}={}.{}; local {}={}.{}; ",
            fn_bx, var_shell, k_bx, fn_ba, var_shell, k_band, fn_bs, var_shell, k_rshift
        ));
        let tbl_def = format!(
            "local {p}={{}};{p}[{g1}]={{}};{p}[{g1}][{bx}]={fbx};{p}[{g1}][{add}]=function(a,b)return a+b end;{p}[{g1}][{ba}]={fba};{p}[{g2}]={{}};{p}[{g2}][{ba2}]=function(a)return {fba}(a,{max_u32})end;{p}[{g2}][{bs2}]=function(a)return {fbs}(a,{one})end;",
            p = keys.tbl_p,
            g1 = rng.format_num(keys.grp1 as i64),
            g2 = rng.format_num(keys.grp2 as i64),
            bx = rng.format_num(keys.key_bx as i64),
            add = rng.format_num(keys.key_add as i64),
            ba = rng.format_num(keys.key_ba as i64),
            ba2 = rng.format_num(keys.key_ba2 as i64),
            bs2 = rng.format_num(keys.key_bs2 as i64),
            fbx = fn_bx,
            fba = fn_ba,
            fbs = fn_bs,
            max_u32 = rng.format_num(4294967295i64),
            one = rng.format_num(1i64)
        );
        block_p_def.push_str(&tbl_def);

        let block_vm_core = Lua_core::build_vm_core().replace("\n", " ");
        
        let (payload_str, decoder_script, entry_func) = Packer::pack(&combined_payload, &mut rng);
        let var_junk = rng.name(); let var_vc = rng.name(); let var_builtin_reg = rng.name();
        let gget = rng.name(); let gset = rng.name();
        let block_packer_vars = format!("local {}, {}, {}, {}, {}; ", var_junk, var_vc, var_builtin_reg, gget, gset);

        let fn_execute = "execute";
        let var_pc = rng.name();
        let var_stk = rng.name();
        let var_top = rng.name();
        let var_inst = rng.name();
        let var_varargs = rng.name();
        let var_varargs_len = rng.name();
        let var_insts = rng.name();
        let var_opcodes = rng.name();
        let var_a_arr = rng.name();
        let var_b_arr = rng.name();
        let var_c_arr = rng.name();
        let mut block_execute_def = String::new();
        block_execute_def.push_str(&format!("local function {}(chunk, env, upvals, ...) ", fn_execute));
        block_execute_def.push_str(&format!("local {} = function(...) return {}[{}]('#', ...) end; ", var_get_count, var_s, hex_select_idx));
        block_execute_def.push_str(&format!("local {} = {}(...); ", var_L, var_get_count));
        block_execute_def.push_str(&format!("local unpack, zm = {}.{}, function(...) return {{n={}(...),...}} end; ", var_shell, k_unpack, var_get_count));
        block_execute_def.push_str(&format!("local {}, {}, {}, {}, {}, {}, {} = chunk.opcodes, chunk.a_arr, chunk.b_arr, chunk.c_arr, 1, {{}}, 0; ", var_opcodes, var_a_arr, var_b_arr, var_c_arr, var_pc, var_stk, var_top));
        block_execute_def.push_str(&format!("for _=1,chunk.numparams do {}[_-1] = {}[{}](_,...) end; ", var_stk, var_s, hex_select_idx));
        block_execute_def.push_str(&format!("local {} = {} - chunk.numparams; local {} = {{{}[{}](chunk.numparams + 1, ...)}}; ", var_varargs_len, var_L, var_varargs, var_s, hex_select_idx));
        block_execute_def.push_str("while true do ");
        block_execute_def.push_str(&format!("{} = true; ", var_state_flag));
        block_execute_def.push_str(&format!("local op = {}[{}]; ", var_opcodes, var_pc));
        block_execute_def.push_str(&format!("local inst_A = {}[{}]; ", var_a_arr, var_pc));
        block_execute_def.push_str(&format!("local inst_B = {}[{}]; ", var_b_arr, var_pc));
        block_execute_def.push_str(&format!("local inst_C = {}[{}]; ", var_c_arr, var_pc));
        block_execute_def.push_str(&format!("{} = {} + 1; ", var_pc, var_pc));
        
        let cfg = OpcodeConfig { pc: var_pc.clone(), stk: var_stk.clone(), consts: "chunk.consts".to_string(), top: var_top.clone(), insts: var_insts.clone(), inst: var_inst.clone(), upvals: "upvals".to_string(), env: "env".to_string(), protos: "chunk.protos".to_string(), handlers: String::new(), varargs: var_varargs.clone(), varargs_len: var_varargs_len.clone(), virtual_closures: var_vc.clone(), builtin_reg: var_builtin_reg.clone(), global_get: gget.clone(), global_set: gset.clone() };
        let mut raw_handlers = Opcodes::generate_handlers(&mapped_opcodes, &cfg, self.ctx.seed).replace("execute(", &format!("{}(", fn_execute));
        
        raw_handlers = raw_handlers.replace(
            &format!("{}[{}][1]", var_insts, var_pc),
            &format!("{}[{}]", var_opcodes, var_pc)
        ).replace(
            &format!("{}[{}][2]", var_insts, var_pc),
            &format!("{}[{}]", var_a_arr, var_pc)
        ).replace(
            &format!("{}[{}][3]", var_insts, var_pc),
            &format!("{}[{}]", var_b_arr, var_pc)
        ).replace(
            &format!("{}[{}][4]", var_insts, var_pc),
            &format!("{}[{}]", var_c_arr, var_pc)
        ).replace(
            &format!("{}[{}]", var_insts, var_pc),
            &format!("({{ {}[{}], {}[{}], {}[{}], {}[{}] }})", var_opcodes, var_pc, var_a_arr, var_pc, var_b_arr, var_pc, var_c_arr, var_pc)
        ).replace(
            &format!("{}[1]", var_inst), "op"
        ).replace(
            &format!("{}[2]", var_inst), "inst_A"
        ).replace(
            &format!("{}[3]", var_inst), "inst_B"
        ).replace(
            &format!("{}[4]", var_inst), "inst_C"
        ).replace(
            &var_inst, "({op, inst_A, inst_B, inst_C})"
        );

        if raw_handlers.trim_start().starts_with("if op") { raw_handlers = raw_handlers.replacen("if op", "elseif op", 1); }

        let mut handlers_list: Vec<(u32, String)> = Vec::new();
        let mut remaining = raw_handlers.as_str();
        let mut current_ops: Vec<u32> = Vec::new(); let mut current_code = String::new();
        
        while let Some(idx) = remaining.find("elseif op") {
            let before = &remaining[..idx];
            if !current_ops.is_empty() {
                current_code.push_str(before); let code_str = current_code.trim().to_string();
                for &op in &current_ops { handlers_list.push((op, code_str.clone())); }
                current_code.clear();
            }
            remaining = &remaining[idx + 9..];
            if let Some(then_idx) = remaining.find("then") {
                let ops: Vec<u32> = remaining[..then_idx].split(|c: char| !c.is_numeric()).filter_map(|s| s.parse::<u32>().ok()).collect();
                if !ops.is_empty() { current_ops = ops; remaining = &remaining[then_idx + 4..]; } else { current_code.push_str("elseif op"); current_code.push_str(&remaining[..then_idx]); current_code.push_str("then"); remaining = &remaining[then_idx + 4..]; }
            }
        }
        if !current_ops.is_empty() {
            current_code.push_str(remaining); let code_str = current_code.trim().to_string();
            for &op in &current_ops { handlers_list.push((op, code_str.clone())); }
        }
        handlers_list.sort_by_key(|h| h.0);

        if !handlers_list.is_empty() { 
            block_execute_def.push_str(&build_opcode_tree(&handlers_list, 0, handlers_list.len() - 1, "op", &keys, &mut rng)); 
            block_execute_def.push_str(&format!(" end; {} = false; end; ", var_state_flag)); 
        } else { 
            let mut f = raw_handlers.replacen("elseif", "if", 1); 
            f.push_str(" end "); 
            block_execute_def.push_str(&f); 
            block_execute_def.push_str(&format!(" {} = false; end; ", var_state_flag)); 
        }

        let block_decoder_script = decoder_script.replace("\n", " ");
        
        let var_idx = rng.name(); let var_b = rng.name(); let var_tamper = rng.name(); let fn_s_byte = rng.name(); let fn_s_sub = rng.name(); let var_raw_p = rng.name(); let var_chk = rng.name(); let var_p = rng.name(); let var_a2 = rng.name(); let fn_a3 = rng.name(); let x = rng.name(); let var__a = rng.name(); let var__b = rng.name(); let fn_read_dec = rng.name(); let fn_bxor = rng.name(); let fn_b_rotr = rng.name(); let fn_a5 = rng.name(); let fn_read_string = rng.name(); let fn_a10 = rng.name(); let fn_dec_num = rng.name(); let fn_dec_str = rng.name(); let global_strings = rng.name(); let global_numbers = rng.name(); let fn_decode_chunk = rng.name(); let fn_u32_dec = rng.name(); let l = rng.name(); let s_t = rng.name(); let v = rng.name(); let v_sign = rng.name(); let v_exp = rng.name(); let v_mant = rng.name(); let t = rng.name(); let fn_c = rng.name();
        let var_boot_env = rng.name(); let var_bname = rng.name();

        let fn_qr = rng.name();
        let fn_xor32 = rng.name();
        let fn_rotl32 = rng.name();
        let fn_chacha_block = rng.name();
        let fn_chacha_stream = rng.name();
        let xor_tbl_var = rng.name();
        let chacha_key_var = rng.name();
        let chacha_salt_var = rng.name();
        let kind_str_obf = rng.obfuscate_num(0i64, 1, &keys);
        let kind_num_obf = rng.obfuscate_num(1i64, 1, &keys);
        let chacha_key_lua = (0..8).map(|i| rng.obfuscate_num(chacha_key[i] as i64, 1, &keys)).collect::<Vec<_>>().join(",");
        let chacha_salt_lua = rng.obfuscate_num(chacha_salt as i64, 1, &keys);

        let mut block_chacha_setup = String::new();
        block_chacha_setup.push_str(&format!(
            "local {xt}={{}}; for a=0,255 do local row={{}}; for b=0,255 do local x,y,r,p=a,b,0,1; while x>0 or y>0 do local rx,ry=x%2,y%2; if rx~=ry then r=r+p end; x,y,p=math_floor(x/2),math_floor(y/2),p*2 end; row[b]=r end; {xt}[a]=row end; ",
            xt = xor_tbl_var
        ));
        block_chacha_setup.push_str(&format!(
            "local function {xor32}(a,b) local a1,a2,a3,a4=a%256,math_floor(a/256)%256,math_floor(a/65536)%256,math_floor(a/16777216)%256; local b1,b2,b3,b4=b%256,math_floor(b/256)%256,math_floor(b/65536)%256,math_floor(b/16777216)%256; return {xt}[a1][b1]+{xt}[a2][b2]*256+{xt}[a3][b3]*65536+{xt}[a4][b4]*16777216 end; ",
            xor32 = fn_xor32, xt = xor_tbl_var
        ));
        block_chacha_setup.push_str(&format!(
            "local function {rotl32}(x,n) local m=2^n; return ((x*m)%4294967296)+math_floor(x/(4294967296/m)) end; ",
            rotl32 = fn_rotl32
        ));
        block_chacha_setup.push_str(&format!(
            "local function {qr}(s,a,b,c,d) s[a]=(s[a]+s[b])%4294967296; s[d]={xor32}(s[d],s[a]); s[d]={rotl32}(s[d],16); s[c]=(s[c]+s[d])%4294967296; s[b]={xor32}(s[b],s[c]); s[b]={rotl32}(s[b],12); s[a]=(s[a]+s[b])%4294967296; s[d]={xor32}(s[d],s[a]); s[d]={rotl32}(s[d],8); s[c]=(s[c]+s[d])%4294967296; s[b]={xor32}(s[b],s[c]); s[b]={rotl32}(s[b],7) end; ",
            qr = fn_qr, xor32 = fn_xor32, rotl32 = fn_rotl32
        ));
        block_chacha_setup.push_str(&format!(
            "local {ckey}={{{key_lua}}}; local {csalt}={salt_lua}; ",
            ckey = chacha_key_var, key_lua = chacha_key_lua, csalt = chacha_salt_var, salt_lua = chacha_salt_lua
        ));
        block_chacha_setup.push_str(&format!(
            "local function {cblock}(n1,n2,n3,ctr) local K={ckey}; local s={{0x61707865,0x3320646e,0x79622d32,0x6b206574,K[1],K[2],K[3],K[4],K[5],K[6],K[7],K[8],ctr,n1,n2,n3}}; local o={{}}; for i=1,16 do o[i]=s[i] end; for _=1,4 do {qr}(s,1,5,9,13); {qr}(s,2,6,10,14); {qr}(s,3,7,11,15); {qr}(s,4,8,12,16); {qr}(s,1,6,11,16); {qr}(s,2,7,12,13); {qr}(s,3,8,9,14); {qr}(s,4,5,10,15) end; local out={{}}; for i=1,16 do local w=(s[i]+o[i])%4294967296; out[(i-1)*4+1]=w%256; out[(i-1)*4+2]=math_floor(w/256)%256; out[(i-1)*4+3]=math_floor(w/65536)%256; out[(i-1)*4+4]=math_floor(w/16777216)%256 end; return out end; ",
            cblock = fn_chacha_block, ckey = chacha_key_var, qr = fn_qr
        ));
        block_chacha_setup.push_str(&format!(
            "local function {cstream}(pool_idx,kind,n) local out={{}}; local ctr=0; local pos=1; while pos<=n do local blk={cblock}({csalt},pool_idx,kind,ctr); for i=1,64 do if pos>n then break end; out[pos]=blk[i]; pos=pos+1 end; ctr=ctr+1 end; return out end; ",
            cstream = fn_chacha_stream, cblock = fn_chacha_block, csalt = chacha_salt_var
        ));
        
        let block_dec_header = format!("local {}, {} = {}, {}; local {} = ([=[KRYVEX{}]=]); local {}, {}, {} = {}, {}, {}; repeat local {}={}({},{}); {}={}+{}; {}={}+{}; {}={}+({}%{}); until {}>={}; {} = ({}-{}) + ({}-{}); {}={}+(type({})=='function' and 0 or {}); local mt_vc={{}}; mt_vc[\"__\"..\"mode\"]='k'; {} = setmetatable({{}}, mt_vc); local {}, {} = {}({}({},{}+{}*{})), {}; local function {}() local {}={}({},{},{}); {}={}+{}; return {} end; local k1,k2,k3,k4 = {}(),{}(),{}(),{}(); ", fn_s_byte, fn_s_sub, "string_byte", "string_sub", var_raw_p, payload_str, var_chk, var_idx, var_junk, rng.obfuscate_num(0i64, 1, &keys), rng.obfuscate_num(1i64, 1, &keys), rng.obfuscate_num(0i64, 1, &keys), var_b, fn_s_byte, var_raw_p, var_idx, var_chk, var_chk, var_b, var_idx, var_idx, rng.obfuscate_num(1i64, 1, &keys), var_junk, var_junk, var_b, rng.obfuscate_num(2i64, 1, &keys), var_idx, rng.obfuscate_num(7i64, 1, &keys), var_tamper, var_chk, var_chk, var_junk, var_junk, var_tamper, var_tamper, fn_s_byte, rng.obfuscate_num(73i64, 1, &keys), var_vc, var_p, var_a2, entry_func, fn_s_sub, var_raw_p, var_idx, var_tamper, rng.obfuscate_num(1337i64, 2, &keys), rng.obfuscate_num(1i64, 1, &keys), fn_a3, x, fn_s_byte, var_p, var_a2, var_a2, var_a2, var_a2, rng.obfuscate_num(1i64, 1, &keys), x, fn_a3, fn_a3, fn_a3, fn_a3);
        let block_dec_helpers = format!("local function {}(a, b) local r, p, c = 0, 1, 0; while a > 0 or b > 0 do local ra, rb = a % 2, b % 2; if ra ~= rb then c = c + p end; a, b, p = math_floor(a / 2), math_floor(b / 2), p * 2 end; return c end; local function {}(x, n) if n == 0 then return x end return ((x * (2^(8-n))) % 256) + math_floor(x / (2^n)) end; local function {}() local enc = {}(); local dec = (enc - 66 + 256) % 256; dec = {}(dec, k4); dec = {}(dec, k3 % 8); dec = (dec + k2) % 256; dec = {}(dec, k1); local orig = dec; k1 = (k1 + orig) % 256; k1 = ((k1 * 2) % 256) + math_floor(k1 / 128); k1 = (k1 + 27) % 256; k2 = (k2 * 3 + enc) % 256; k2 = ((k2 * 64) % 256) + math_floor(k2 / 4); k3 = {}(k3, (k1 - k4 + 256) % 256); k4 = (k4 + k2) % 256; k4 = ((k4 * 8) % 256) + math_floor(k4 / 32); return orig end; ", fn_bxor, fn_b_rotr, fn_read_dec, fn_a3, fn_bxor, fn_b_rotr, fn_bxor, fn_bxor);
        let block_dec_readers = format!("local function {}() local {}={{}}; for i=1,4 do {}[i]={}() end; return {}[1]+({}[2]*256)+({}[3]*65536)+({}[4]*16777216) end; local function {}() local {}={{}}; for i=1,4 do {}[i]={}() end; return {}[1]+({}[2]*{})+({}[3]*{})+({}[4]*{}) end; local function {}() local {}={}(); if {}=={} then return '' end; local {}={{}}; for _={},{} do {}[_]=string_char({}()) end; return table_concat({}) end; local function {}() local {}={}(); if {}>=2^31 then return {}-2^32 else return {} end end; ", fn_u32_dec, var__a, var__a, fn_read_dec, var__a, var__a, var__a, var__a, fn_a5, var__a, var__a, fn_a3, var__a, var__a, rng.obfuscate_num(256i64, 1, &keys), var__a, rng.obfuscate_num(65536i64, 1, &keys), var__a, rng.obfuscate_num(16777216i64, 1, &keys), fn_read_string, l, fn_a5, l, rng.obfuscate_num(0i64, 1, &keys), s_t, rng.obfuscate_num(1i64, 1, &keys), l, s_t, fn_a3, s_t, fn_a10, v, fn_a5, v, v, v);
        
        let mut f64_parts = vec![format!("({}[7]%16)*2^48", var__b), format!("({}[6]*2^40)", var__b), format!("({}[5]*2^32)", var__b), format!("({}[4]*2^24)", var__b), format!("({}[3]*2^16)", var__b), format!("({}[2]*2^8)", var__b), format!("{}[1]", var__b)];
        rng.shuffle(&mut f64_parts);

        let block_dec_numbers = format!(
            "local function {fn_dec_num}(v_enc, pool_idx) local ks={fn_chacha_stream}(pool_idx,{kind_num},8); local {vb}={{}}; for i=1,8 do {vb}[i]={xt}[v_enc[i]][ks[i]] end; local {v_sign} = {vb}[8]>=128 and -1 or 1; local {v_exp} = ({vb}[8]%128)*16+math_floor({vb}[7]/16); local {v_mant} = {f64parts}; if {v_exp}==0 then return {v_sign}*{v_mant}*(2^(-1074)) elseif {v_exp}==2047 then return {v_mant}==0 and {v_sign}*(1/0) or (0/0) else return {v_sign}*({v_mant}+2^52)*(2^({v_exp}-1075)) end end; ",
            fn_dec_num = fn_dec_num, fn_chacha_stream = fn_chacha_stream, kind_num = kind_num_obf, vb = var__b, xt = xor_tbl_var,
            v_sign = v_sign, v_exp = v_exp, v_mant = v_mant, f64parts = f64_parts.join("+"));

        let block_dec_strings = format!(
            "local function {fn_dec_str}(enc_s, pool_idx) local len=#enc_s; local ks={fn_chacha_stream}(pool_idx,{kind_str},len); local s={{}}; for j=1,len do s[j]=string_char({xt}[{fn_s_byte}(enc_s,j)][ks[j]]) end; return table_concat(s) end; ",
            fn_dec_str = fn_dec_str, fn_chacha_stream = fn_chacha_stream, kind_str = kind_str_obf, xt = xor_tbl_var, fn_s_byte = fn_s_byte);

        let block_pools_init_strings = format!("local {gs}={{}}; local str_count={u32d}(); for i=1,str_count do local len={u32d}(); local s={{}}; for j=1,len do s[j]=string_char({rd}()) end; {gs}[i]=table_concat(s); end; ",
            gs = global_strings, u32d = fn_u32_dec, rd = fn_read_dec);

        let block_pools_init_numbers = format!("local {gn}={{}}; local num_count={u32d}(); for i=1,num_count do local v={{}}; for j=1,8 do v[j]={rd}(); end; {gn}[i]=v; end; ",
            gn = global_numbers, u32d = fn_u32_dec, rd = fn_read_dec);

        let var_enc_c = rng.name();
        let var_tbl = rng.name();
        let var_idx_chunk = rng.name();
        let var_e = rng.name();
        let var_cache = rng.name();
        let var_cache_n = rng.name();
        let cache_limit_obf = rng.obfuscate_num(CONST_CACHE_LIMIT, 1, &keys);

        let var_state = rng.name();
        let s_init = rng.range(0x100, 0xFFF) as i64;
        let s_insts = rng.range(0x1000, 0x1FFF) as i64;
        let s_consts = rng.range(0x2000, 0x2FFF) as i64;
        let s_protos = rng.range(0x3000, 0x3FFF) as i64;
        let s_debug = rng.range(0x4000, 0x4FFF) as i64;
        let s_ret = rng.range(0x5000, 0x5FFF) as i64;

        let obf_s_init = rng.format_num(s_init);
        let obf_s_insts = rng.format_num(s_insts);
        let obf_s_consts = rng.format_num(s_consts);
        let obf_s_protos = rng.format_num(s_protos);
        let obf_s_debug = rng.format_num(s_debug);
        let obf_s_ret = rng.format_num(s_ret);
        
        let block_dec_chunk = format!(
            "local function {fn_dec_chunk}() \
                local {fn_c}, {t}, {var_state} = {{}}, nil, {obf_s_init}; \
                while true do \
                    if {var_state} == {obf_s_init} then \
                        {fn_c}.n={fn_read_string}(); \
                        {fn_c}.ld={fn_a5}(); \
                        {fn_c}.lld={fn_a5}(); \
                        {fn_c}.nups={fn_a3}(); \
                        {fn_c}.numparams={fn_a3}(); \
                        {fn_c}.is_vararg={fn_a3}(); \
                        {fn_c}.maxstack={fn_a3}(); \
                        {var_state} = {obf_s_insts}; \
                    elseif {var_state} == {obf_s_insts} then \
                        {fn_c}.opcodes={{}}; \
                        {fn_c}.a_arr={{}}; \
                        {fn_c}.b_arr={{}}; \
                        {fn_c}.c_arr={{}}; \
                        for _={one_obf},{fn_a5}() do \
                            {fn_c}.opcodes[_]={fn_a5}(); \
                            {fn_c}.a_arr[_]={fn_a3}(); \
                            {fn_c}.b_arr[_]={fn_a10}(); \
                            {fn_c}.c_arr[_]={fn_a10}(); \
                        end; \
                        {var_state} = {obf_s_consts}; \
                    elseif {var_state} == {obf_s_consts} then \
                        local {var_enc_c}={{}}; \
                        local {var_cache}={{}}; \
                        local {var_cache_n}={zero_obf2}; \
                        local mt_consts={{}}; \
                        mt_consts[\"__\"..\"index\"]=function({var_tbl},{var_idx_chunk}) \
                            if not {var_state_flag} then \
                                return \"KryvexObf_\"..{var_idx_chunk} \
                            end; \
                            local cached={var_cache}[{var_idx_chunk}]; \
                            if cached~=nil then \
                                return cached \
                            end; \
                            local {var_e}={var_enc_c}[{var_idx_chunk}]; \
                            if not {var_e} then \
                                return nil \
                            end; \
                            local val; \
                            if {var_e}[1]=={one_obf} then \
                                val={var_e}[2] \
                            elseif {var_e}[1]=={two_obf} then \
                                val={fn_dec_num}({var_e}[2],{var_e}[3]) \
                            elseif {var_e}[1]=={three_obf} then \
                                val={fn_dec_str}({var_e}[2],{var_e}[3]) \
                            end; \
                            {var_cache}[{var_idx_chunk}]=val; \
                            {var_cache_n}={var_cache_n}+{one_obf}; \
                            if {var_cache_n}>=({cache_limit_obf}) then \
                                {var_cache}={{}}; \
                                {var_cache_n}={zero_obf2}; \
                            end; \
                            return val \
                        end; \
                        {fn_c}.consts=setmetatable({{}},mt_consts); \
                        for _={one_obf},{fn_a5}() do \
                            {t}={fn_a3}(); \
                            if {t}=={one_obf} then \
                                {var_enc_c}[_]={{1,{fn_a3}()~={zero_obf}}} \
                            elseif {t}=={two_obf} then \
                                local raw_idx={fn_a5}(); \
                                local idx=raw_idx+1; \
                                {var_enc_c}[_]={{2,{global_numbers}[idx],raw_idx}} \
                            elseif {t}=={three_obf} then \
                                local raw_idx={fn_a5}(); \
                                local idx=raw_idx+1; \
                                {var_enc_c}[_]={{3,{global_strings}[idx],raw_idx}} \
                            end \
                        end; \
                        {var_state} = {obf_s_protos}; \
                    elseif {var_state} == {obf_s_protos} then \
                        {fn_c}.protos={{}}; \
                        for _={one_obf},{fn_a5}() do \
                            {fn_c}.protos[_]={fn_dec_chunk}() \
                        end; \
                        {var_state} = {obf_s_debug}; \
                    elseif {var_state} == {obf_s_debug} then \
                        for _={one_obf},{fn_a5}() do \
                            {fn_a5}() \
                        end; \
                        for _={one_obf},{fn_a5}() do \
                            {fn_read_string}();{fn_a5}();{fn_a5}() \
                        end; \
                        for _={one_obf},{fn_a5}() do \
                            {fn_read_string}() \
                        end; \
                        {var_state} = {obf_s_ret}; \
                    elseif {var_state} == {obf_s_ret} then \
                        return {fn_c} \
                    end \
                end \
            end; ",
            fn_dec_chunk = fn_decode_chunk,
            fn_c = fn_c,
            t = t,
            var_state = var_state,
            obf_s_init = obf_s_init,
            obf_s_insts = obf_s_insts,
            obf_s_consts = obf_s_consts,
            obf_s_protos = obf_s_protos,
            obf_s_debug = obf_s_debug,
            obf_s_ret = obf_s_ret,
            fn_read_string = fn_read_string,
            fn_a5 = fn_a5,
            fn_a3 = fn_a3,
            one_obf = rng.obfuscate_num(1i64, 1, &keys),
            fn_a10 = fn_a10,
            var_enc_c = var_enc_c,
            var_cache = var_cache,
            var_cache_n = var_cache_n,
            zero_obf2 = rng.format_num(0),
            cache_limit_obf = cache_limit_obf,
            var_tbl = var_tbl,
            var_idx_chunk = var_idx_chunk,
            var_state_flag = var_state_flag,
            var_e = var_e,
            fn_dec_num = fn_dec_num,
            fn_dec_str = fn_dec_str,
            zero_obf = rng.obfuscate_num(0i64, 1, &keys),
            two_obf = rng.obfuscate_num(2i64, 1, &keys),
            three_obf = rng.obfuscate_num(3i64, 1, &keys),
            global_numbers = global_numbers,
            global_strings = global_strings
        );

        let mut parts = vec![
            block_p_def,
            block_vm_core,
            block_packer_vars,
            block_execute_def,
            block_decoder_script,
            block_dec_header,
            block_dec_helpers,
            block_dec_readers,
            block_chacha_setup,
            block_dec_numbers,
            block_dec_strings,
            block_pools_init_strings,
            block_pools_init_numbers,
            block_dec_chunk,
        ];

        let mut shuffled_guards = at.guards.clone();
        rng.shuffle(&mut shuffled_guards);

        for guard in shuffled_guards {
            let gap_idx = rng.range(0, parts.len() + 1);
            parts.insert(gap_idx, guard);
        }

        let mut out = String::new();
        out.push_str(&format!("local {} = ...;\n", var_l));
        out.push_str(&header_block);
        out.push_str(&format!("local math_floor, string_char, string_sub, string_byte, table_concat = {}.{}, {}.{}, {}.{}, {}.{}, {}.{}; local math_random = {}.{}; local setmetatable = {}.{}; local type = {}.{}; local pairs = {}.{}; local pcall = {}.{}; local bxor_fn, band_fn, bor_fn, lshift_fn, rshift_fn, bnot_fn = {}.{}, {}.{}, {}.{}, {}.{}, {}.{}, {}.{}; ",
            var_shell, k_floor, var_shell, k_char, var_shell, k_sub, var_shell, k_byte, var_shell, k_concat,
            var_shell, k_random, var_shell, k_setmt, var_shell, k_type, var_shell, k_pairs, var_shell, k_pcall,
            var_shell, k_bx, var_shell, k_band, var_shell, k_bor, var_shell, k_lshift, var_shell, k_rshift, var_shell, k_bnot));
        out.push_str(&at.setup);
        out.push_str(&format!(" local {} = 0; ", key_seed_var));
        out.push_str(" ");

        for part in parts {
            out.push_str(&part);
            out.push_str(" ");
        }

        out.push_str(&format!("local main_chunk={}(); ", fn_decode_chunk));
        out.push_str(&at.trigger);
        out.push_str(&format!(" {} = {{}}; local {} = (getfenv and getfenv() or _ENV or _G); local {}; ", var_builtin_reg, var_boot_env, var_bname));
        for (i, name) in Opcodes::builtins::BUILTIN_NAMES.iter().enumerate() {
            let slot = builtin_slot_perm[i];
            let raw_idx = builtin_pool_indices[i];
            let lua_idx = raw_idx + 1;
            out.push_str(&format!(
                "{bname}={fn_dec_str}({gs}[{lidx}],{ridx}); {reg}[{slot}]={benv}[{bname}]; if {reg}[{slot}]==nil and getgenv then {reg}[{slot}]=getgenv()[{bname}] end; ",
                bname = var_bname, fn_dec_str = fn_dec_str, gs = global_strings,
                lidx = lua_idx, ridx = raw_idx, reg = var_builtin_reg, slot = slot + 1, benv = var_boot_env
            ));
            let _ = name;
        }
        let n_real = global_boot.len();
        let n_decoy = decoy_entries.len();
        let mut emission = std::mem::take(&mut global_boot);
        emission.extend(decoy_entries);
        rng.shuffle(&mut emission);
        if !emission.is_empty() {
            out.push_str(&format!(" {} = {{}}; {} = {{}}; ", gget, gset));
            for (raw_idx, aliases) in &emission {
                let lua_idx = raw_idx + 1;
                out.push_str(&format!(
                    "{}={}({}[{}],{}); ",
                    var_bname, fn_dec_str, global_strings, lua_idx, raw_idx
                ));
                for slot in aliases {
                    let alias_obf = rng.obfuscate_num(*slot as i64, 1, &keys);
                    out.push_str(&format!(
                        "{}[{}]=(function(nm) return function(e) local v=e[nm]; if v==nil and getgenv then v=getgenv()[nm] end; return v end end)({}); ",
                        gget, alias_obf, var_bname
                    ));
                    out.push_str(&format!(
                        "{}[{}]=(function(nm) return function(e, val) e[nm]=val; if getgenv then getgenv()[nm]=val end end end)({}); ",
                        gset, alias_obf, var_bname
                    ));
                }
            }
        }

        let fu = rng.name();
        
        out.push_str(" ");
        out.push_str(&format!("return {}(main_chunk, {}, {{}}, {}) end,{}=function(x) x:{}() end", fn_execute, var_boot_env, var_l, fu, wai));
        out.push_str(&format!(",{}=select,{}=math.floor,{}=math.random,{}=string.char,{}=string.byte,{}=string.sub,{}=table.concat,{}=unpack or table and table.unpack or function() end,{}=pcall,{}=setmetatable,{}=type,{}=pairs,{}=bit32 and bit32.bxor or bit and bit.bxor or function(a,b)a,b=a%4294967296,b%4294967296;local r,p=0,1;while a>0 or b>0 do local ra,rb=a%2,b%2;if ra~=rb then r=r+p end;a,b,p=(a-a%1)/2,(b-b%1)/2,p*2 end;return r end,{}=bit32 and bit32.band or bit and bit.band or function(a,b)a,b=a%4294967296,b%4294967296;local r,p=0,1;while a>0 and b>0 do local ra,rb=a%2,b%2;if ra==1 and rb==1 then r=r+p end;a,b,p=(a-a%1)/2,(b-b%1)/2,p*2 end;return r end,{}=bit32 and bit32.bor or bit and bit.bor or function(a,b)a,b=a%4294967296,b%4294967296;local r,p=0,1;while a>0 or b>0 do local ra,rb=a%2,b%2;if ra==1 or rb==1 then r=r+p end;a,b,p=(a-a%1)/2,(b-b%1)/2,p*2 end;return r end,{}=bit32 and bit32.lshift or bit and (bit.lshift or bit.lsh) or function(a,n)a=a%4294967296;return (a*(2^n))%4294967296 end,{}=bit32 and bit32.rshift or bit and bit.rshift or function(a,n)a=a%4294967296;return (a - a % (2^n)) / (2^n) end,{}=bit32 and bit32.bnot or bit and bit.bnot or function(a)a=a%4294967296;return 4294967295 - a end",
            k_sel, k_floor, k_random, k_char, k_byte, k_sub, k_concat, k_unpack, k_pcall, k_setmt, k_type, k_pairs, k_bx, k_band, k_bor, k_lshift, k_rshift, k_bnot));
        out.push_str(&format!(" }}):{}()", fu));
        out
    }
}