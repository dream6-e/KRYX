// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use crate::VM::VM_Backend::Context::VmContext;
use crate::VM::VM_Backend::Lua_core;
use crate::VM::Opcodes::{self, OpcodeConfig};
use crate::VM::packer::Packer;
use crate::compiler::instructions::{OpCode, OpMode, OpArgMask};
use std::collections::{HashMap, HashSet};
use rand::{rng, Rng, SeedableRng};
use rand::rngs::StdRng;
use super::AntiTamper;

fn chacha_qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(7);
}

fn chacha8_block(key: &[u32; 8], nonce: [u32; 3], counter: u32) -> [u8; 64] {
    let mut s: [u32; 16] = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
        counter, nonce[0], nonce[1], nonce[2],
    ];
    let orig = s;
    for _ in 0..4 {
        chacha_qr(&mut s, 0, 4, 8, 12);
        chacha_qr(&mut s, 1, 5, 9, 13);
        chacha_qr(&mut s, 2, 6, 10, 14);
        chacha_qr(&mut s, 3, 7, 11, 15);
        chacha_qr(&mut s, 0, 5, 10, 15);
        chacha_qr(&mut s, 1, 6, 11, 12);
        chacha_qr(&mut s, 2, 7, 8, 13);
        chacha_qr(&mut s, 3, 4, 9, 14);
    }
    for i in 0..16 { s[i] = s[i].wrapping_add(orig[i]); }
    let mut out = [0u8; 64];
    for i in 0..16 { out[i * 4..i * 4 + 4].copy_from_slice(&s[i].to_le_bytes()); }
    out
}

fn chacha8_keystream(key: &[u32; 8], nonce: [u32; 3], n_bytes: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n_bytes + 64);
    let mut counter = 0u32;
    while out.len() < n_bytes {
        out.extend_from_slice(&chacha8_block(key, nonce, counter));
        counter = counter.wrapping_add(1);
    }
    out.truncate(n_bytes);
    out
}

fn chacha8_xor(key: &[u32; 8], salt: u32, pool_idx: u32, kind: u32, data: &[u8]) -> Vec<u8> {
    let nonce = [salt, pool_idx, kind];
    let ks = chacha8_keystream(key, nonce, data.len());
    data.iter().zip(ks.iter()).map(|(b, k)| b ^ k).collect()
}

pub struct CipherKeys {
    pub grp1: u64,
    pub grp2: u64,
    pub key_bx: u64,
    pub key_ba: u64,
    pub key_add: u64,
    pub key_bs: u64,
    pub key_ba2: u64,
    pub key_bs2: u64,
    pub tbl_p: String,
}

pub struct ControlFlowBuilder;

impl ControlFlowBuilder {
    pub fn format_num(val: i64, rng: &mut GenRng) -> String {
        match rng.range(0, 3) {
            0 => {
                if val < 0 {
                    format!("-0x{:x}", val.unsigned_abs())
                } else {
                    format!("0x{:x}", val)
                }
            }
            1 => val.to_string(),
            _ => {
                let lit = crate::VM::numlit::random_binary_literal(val.unsigned_abs());
                if val < 0 { format!("-{lit}") } else { lit }
            }
        }
    }

    pub fn obfuscate_num_depth(val: i64, depth: usize, keys: &CipherKeys, rng: &mut GenRng) -> String {
        if depth == 0 {
            return Self::format_num(val, rng);
        }

        let style = rng.range(0, 10);
        if style < 4 {
            let huge = rng.range(0x100, 0x2FFF) as i64;
            let offset = val.wrapping_add(huge);
            format!("({}-{})", 
                Self::obfuscate_num_depth(offset, depth - 1, keys, rng), 
                Self::obfuscate_num_depth(huge, depth - 1, keys, rng)
            )
        } else if style < 7 {
            let mask = rng.range(0x10, 0x2FFF) as i64;
            let xor_val = val ^ mask;
            format!("{}[{}][{}]({},{})", 
                keys.tbl_p,
                Self::format_num(keys.grp1 as i64, rng),
                Self::format_num(keys.key_bx as i64, rng),
                Self::obfuscate_num_depth(xor_val, depth - 1, keys, rng), 
                Self::obfuscate_num_depth(mask, depth - 1, keys, rng)
            )
        } else {
            let mask = rng.range(0x10, 0x2FFF) as i64;
            let add_val = val.wrapping_sub(mask);
            format!("{}[{}][{}]({},{})", 
                keys.tbl_p,
                Self::format_num(keys.grp1 as i64, rng),
                Self::format_num(keys.key_add as i64, rng),
                Self::obfuscate_num_depth(add_val, depth - 1, keys, rng), 
                Self::obfuscate_num_depth(mask, depth - 1, keys, rng)
            )
        }
    }

    pub fn generate_opaque_predicate(val: i64, var_name: &str, comp_op: &str, keys: &CipherKeys, rng: &mut GenRng) -> String {
        // opaque predicate 里的 key / 伪常量全部取自复用池，不再每次抽新的大数
        let key = crate::VM::cf_wrap::big_num(rng);
        let mutated_val = val.wrapping_add(key);
        format!("{}[{}][{}]({}<={} and {} or {},{}){}{}", 
            keys.tbl_p,
            Self::format_num(keys.grp1 as i64, rng),
            Self::format_num(keys.key_add as i64, rng),
            var_name, 
            var_name, 
            var_name, 
            Self::format_num(crate::VM::cf_wrap::big_num(rng), rng), 
            Self::format_num(key, rng), 
            comp_op,
            Self::format_num(mutated_val, rng)
        )
    }

    pub fn build_fast_router(
        var_pc: &str,
        var_insts: &str,
        var_inst: &str,
        var_handlers: &str,
        var_r_flg: &str,
        var_r_vals: &str,
        var_r_len: &str,
        var_tamper: &str,
        var_tail_flg: &str,
        var_unpack: &str,
        rng: &mut GenRng,
    ) -> String {
        let keys = CipherKeys {
            grp1: rng.range(0x10, 0x7F) as u64,
            grp2: rng.range(0x10, 0x7F) as u64,
            key_bx: rng.range(0x10, 0x7F) as u64,
            key_ba: rng.range(0x10, 0x7F) as u64,
            key_add: rng.range(0x10, 0x7F) as u64,
            key_bs: rng.range(0x10, 0x7F) as u64,
            key_ba2: rng.range(0x10, 0x7F) as u64,
            key_bs2: rng.range(0x10, 0x7F) as u64,
            tbl_p: rng.name(),
        };

        let s_state = rng.name();
        let t_shadow = rng.name();
        let q_route = rng.name();
        let d_junk = rng.name();
        let f_tmp = rng.name();
        let var_t = rng.name();

        let fn_bx = "_BX";
        let fn_ba = "_BA";
        let fn_bs = "_BS";

        let num_routes = rng.range(16, 28) as i64;
        let mut junk_limit = rng.range(5, 12);

        let mut out = String::new();

        out.push_str(&format!("local {}=bxor_fn;local {}=band_fn;local {}=rshift_fn;", fn_bx, fn_ba, fn_bs));
        
        let tbl_def = format!(
            "local {p}={{}};{p}[{g1}]={{}};{p}[{g1}][{bx}]={fbx};{p}[{g1}][{add}]=function(a_,b_)return a_+b_ end;{p}[{g1}][{ba}]={fba};{p}[{g2}]={{}};{p}[{g2}][{ba2}]=function(a_)return {fba}(a_,{max_u32})end;{p}[{g2}][{bs2}]=function(a_)return {fbs}(a_,{one})end;",
            p = keys.tbl_p,
            g1 = Self::format_num(keys.grp1 as i64, rng),
            g2 = Self::format_num(keys.grp2 as i64, rng),
            bx = Self::format_num(keys.key_bx as i64, rng),
            add = Self::format_num(keys.key_add as i64, rng),
            ba = Self::format_num(keys.key_ba as i64, rng),
            ba2 = Self::format_num(keys.key_ba2 as i64, rng),
            bs2 = Self::format_num(keys.key_bs2 as i64, rng),
            fbx = fn_bx,
            fba = fn_ba,
            fbs = fn_bs,
            max_u32 = Self::format_num(4294967295i64, rng),
            one = Self::format_num(1i64, rng)
        );
        out.push_str(&tbl_def);

        out.push_str(&format!("local {},{},{},{},{},{};", s_state, t_shadow, d_junk, q_route, f_tmp, var_t));
        
        let fetch_state = rng.range(0x1000, 0x2FFF) as i64;
        let init_val1 = rng.range(10, 1000) as i64;
        let init_val2 = rng.range(1, 1000) as i64;
        
        out.push_str(&format!("{},{},{},{}={},{},{},{};", 
            s_state, t_shadow, d_junk, var_t, 
            Self::format_num(init_val1, rng), 
            Self::format_num(0, rng), 
            Self::format_num(init_val2, rng), 
            Self::obfuscate_num_depth(fetch_state, 1, &keys, rng)
        ));

        out.push_str("while true do ");
        
        out.push_str(&format!("if {}=={} then ", var_t, Self::obfuscate_num_depth(fetch_state, 1, &keys, rng)));
        out.push_str(&format!("if {}>#{} then return end;", var_pc, var_insts));
        out.push_str(&format!("{},{}={}[{}],{}+{};", var_inst, var_pc, var_insts, var_pc, var_pc, Self::obfuscate_num_depth(1, 1, &keys, rng)));
        
        let q_route_expr = format!("{}[{}][{}]({}[{}][{}]({}[{}],{}),{})", 
            keys.tbl_p, Self::format_num(keys.grp1 as i64, rng), Self::format_num(keys.key_ba as i64, rng),
            keys.tbl_p, Self::format_num(keys.grp1 as i64, rng), Self::format_num(keys.key_add as i64, rng),
            var_inst, Self::format_num(1, rng), s_state,
            Self::format_num(num_routes, rng)
        );
        out.push_str(&format!("{}={};", q_route, q_route_expr));
        
        let dispatch_state = rng.range(0x1000, 0x2FFF) as i64;
        out.push_str(&format!("{}={};", var_t, Self::obfuscate_num_depth(dispatch_state, 1, &keys, rng)));
        
        out.push_str("elseif ");
        out.push_str(&format!("{}=={} then ", var_t, Self::obfuscate_num_depth(dispatch_state, 1, &keys, rng)));
        out.push_str(&Self::generate_recursive_tree(
            0,
            num_routes as usize - 1,
            &q_route,
            var_inst,
            var_handlers,
            var_tamper,
            &s_state,
            &d_junk,
            &f_tmp,
            &var_t,
            fetch_state,
            &mut junk_limit,
            &keys,
            rng
        ));
        
        out.push_str("else ");
        out.push_str(&format!("if {} then if {} then {},{}=false,false;{}={};else return {}({},{},{})end else {}={};end ", 
            var_r_flg, var_tail_flg, var_tail_flg, var_r_flg, var_t, Self::obfuscate_num_depth(fetch_state, 1, &keys, rng), var_unpack, var_r_vals, Self::format_num(1, rng), var_r_len, var_t, Self::obfuscate_num_depth(fetch_state, 1, &keys, rng)
        ));

        out.push_str("end ");
        out
    }

    pub fn generate_leaf_node(
        var_inst: &str,
        var_handlers: &str,
        var_tamper: &str,
        s_state: &str,
        d_junk: &str,
        f_tmp: &str,
        var_t: &str,
        _fetch_state: i64,
        keys: &CipherKeys,
        rng: &mut GenRng,
    ) -> String {
        let next_s = rng.range(0, 512) as i64;
        let next_s_obf = Self::obfuscate_num_depth(next_s, 1, keys, rng);
        let else_state = 0i64;
        let state_transition = format!("{}={};", var_t, Self::obfuscate_num_depth(else_state, 1, keys, rng));
        let leaf_type = rng.range(0, 5);
        let mut node = String::new();
        let idx_1 = Self::format_num(1, rng);

        match leaf_type {
            0 => {
                node.push_str(&format!("{}={}+{};{}={}[{}[{}]+{}];{}({});{}={};{}", 
                    d_junk, d_junk, Self::format_num(1, rng), f_tmp, var_handlers, var_inst, idx_1, var_tamper, f_tmp, var_inst, s_state, next_s_obf, state_transition));
            }
            1 => {
                node.push_str(&format!("repeat {}={}[{}[{}]+{}];{}({});{}={};{}break until false;", 
                    f_tmp, var_handlers, var_inst, idx_1, var_tamper, f_tmp, var_inst, s_state, next_s_obf, state_transition));
            }
            2 => {
                node.push_str(&format!("for _={},{} do {}={}[{}[{}]+{}];{}({});end {}={};{}", 
                    Self::format_num(1, rng), Self::format_num(1, rng), f_tmp, var_handlers, var_inst, idx_1, var_tamper, f_tmp, var_inst, s_state, next_s_obf, state_transition));
            }
            3 => {
                node.push_str(&format!("if {}~={} then {}={}[{}[{}]+{}];{}({});{}={};{}end ", 
                    d_junk, Self::format_num(4294967295i64, rng), f_tmp, var_handlers, var_inst, idx_1, var_tamper, f_tmp, var_inst, s_state, next_s_obf, state_transition));
            }
            _ => {
                node.push_str(&format!("{}={}[{}[{}]+{}];{}({});{}={};{}", 
                    f_tmp, var_handlers, var_inst, idx_1, var_tamper, f_tmp, var_inst, s_state, next_s_obf, state_transition));
            }
        }
        node
    }

    pub fn generate_recursive_tree(
        min: usize,
        max: usize,
        q_route: &str,
        var_inst: &str,
        var_handlers: &str,
        var_tamper: &str,
        s_state: &str,
        d_junk: &str,
        f_tmp: &str,
        var_t: &str,
        fetch_state: i64,
        junk_limit: &mut usize,
        keys: &CipherKeys,
        rng: &mut GenRng,
    ) -> String {
        if min == max {
            let real_leaf = Self::generate_leaf_node(var_inst, var_handlers, var_tamper, s_state, d_junk, f_tmp, var_t, fetch_state, keys, rng);
            if *junk_limit > 0 && rng.range(0, 5) == 0 {
                *junk_limit -= 1;
                let junk_leaf = Self::generate_leaf_node(var_inst, var_handlers, var_tamper, s_state, d_junk, f_tmp, var_t, fetch_state, keys, rng);
                let fake_cond = Self::format_num(rng.range(0x1000, 0x2FFF) as i64, rng);
                return format!("if {}=={} then {} else {} end ", d_junk, fake_cond, junk_leaf, real_leaf);
            }
            return real_leaf;
        }

        let mid = (min + max) / 2;
        let mut branch = String::new();
        let direction = rng.range(0, 2) == 0;

        let comp_expr = Self::generate_opaque_predicate(mid as i64, q_route, "<=", keys, rng);

        if direction {
            branch.push_str(&format!("if {} then ", comp_expr));
            branch.push_str(&Self::generate_recursive_tree(min, mid, q_route, var_inst, var_handlers, var_tamper, s_state, d_junk, f_tmp, var_t, fetch_state, junk_limit, keys, rng));
            
            if *junk_limit > 0 && rng.range(0, 4) == 0 {
                *junk_limit -= 1;
                let junk_leaf = Self::generate_leaf_node(var_inst, var_handlers, var_tamper, s_state, d_junk, f_tmp, var_t, fetch_state, keys, rng);
                let fake_cond = Self::format_num(rng.range(0x1000, 0x2FFF) as i64, rng);
                branch.push_str(&format!("elseif {}=={} then {} ", d_junk, fake_cond, junk_leaf));
            }

            branch.push_str("else ");
            branch.push_str(&Self::generate_recursive_tree(mid + 1, max, q_route, var_inst, var_handlers, var_tamper, s_state, d_junk, f_tmp, var_t, fetch_state, junk_limit, keys, rng));
            branch.push_str("end ");
        } else {
            let rev_comp = Self::generate_opaque_predicate(mid as i64, q_route, ">", keys, rng);

            branch.push_str(&format!("if {} then ", rev_comp));
            branch.push_str(&Self::generate_recursive_tree(mid + 1, max, q_route, var_inst, var_handlers, var_tamper, s_state, d_junk, f_tmp, var_t, fetch_state, junk_limit, keys, rng));
            
            if *junk_limit > 0 && rng.range(0, 4) == 0 {
                *junk_limit -= 1;
                let junk_leaf = Self::generate_leaf_node(var_inst, var_handlers, var_tamper, s_state, d_junk, f_tmp, var_t, fetch_state, keys, rng);
                let fake_cond = Self::format_num(rng.range(0x1000, 0x2FFF) as i64, rng);
                branch.push_str(&format!("elseif {}=={} then {} ", d_junk, fake_cond, junk_leaf));
            }

            branch.push_str("else ");
            branch.push_str(&Self::generate_recursive_tree(min, mid, q_route, var_inst, var_handlers, var_tamper, s_state, d_junk, f_tmp, var_t, fetch_state, junk_limit, keys, rng));
            branch.push_str("end ");
        }
        branch
    }
}

struct PayloadReader<'a> { data: &'a [u8], pos: usize }

impl<'a> PayloadReader<'a> {
    fn read_u8(&mut self) -> u8 { let b = self.data[self.pos]; self.pos += 1; b }
    fn read_u32(&mut self) -> u32 { let b = &self.data[self.pos..self.pos+4]; self.pos += 4; u32::from_le_bytes([b[0], b[1], b[2], b[3]]) }
    fn read_u64(&mut self) -> u64 { let b = &self.data[self.pos..self.pos+8]; self.pos += 8; u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]) }
    fn read_bytes(&mut self, len: usize) -> &'a [u8] { let b = &self.data[self.pos..self.pos+len]; self.pos += len; b }
    fn read_string(&mut self) -> &'a [u8] { let len = self.read_u32(); self.read_bytes(len as usize) }
}

fn write_string(w: &mut Vec<u8>, s: &[u8]) { w.extend_from_slice(&(s.len() as u32).to_le_bytes()); w.extend_from_slice(s); }

fn scan_used_opcodes(r: &mut PayloadReader, used_ops: &mut HashSet<u8>) {
    let name_len = r.read_u32();
    r.read_bytes(name_len as usize);
    r.read_u32(); r.read_u32(); r.read_u8(); r.read_u8(); r.read_u8(); r.read_u8();
    let inst_count = r.read_u32();
    for _ in 0..inst_count {
        used_ops.insert(r.read_u8());
        r.read_u8(); r.read_u32(); r.read_u32();
    }
    let const_count = r.read_u32();
    for _ in 0..const_count {
        let c_type = r.read_u8();
        match c_type {
            0 => {}
            1 => { r.read_u8(); }
            2 => { r.read_u64(); }
            3 => { let s_len = r.read_u32(); r.read_bytes(s_len as usize); }
            _ => panic!(),
        }
    }
    let p_count = r.read_u32();
    for _ in 0..p_count { scan_used_opcodes(r, used_ops); }
    let l_count = r.read_u32();
    r.read_bytes((l_count * 4) as usize);
    let loc_count = r.read_u32();
    for _ in 0..loc_count { let s_len = r.read_u32(); r.read_bytes(s_len as usize); r.read_u32(); r.read_u32(); }
    let upv_count = r.read_u32();
    for _ in 0..upv_count { let s_len = r.read_u32(); r.read_bytes(s_len as usize); }
}

// Phase 3：全局槽位化上下文（跨所有 chunk 共享，重写时填充，启动期消费）
pub(crate) struct GlobalSlotInfo {
    pub aliases: Vec<u64>,
    pub refcount: u32,
}

pub(crate) struct GlobalSlotCtx {
    pub refcounts: HashMap<Vec<u8>, u32>,   // 预扫描得到的编译期全局引用次数
    pub by_name: HashMap<Vec<u8>, GlobalSlotInfo>, // 槽位化的全局名 → 别名表
    pub used_slots: HashSet<u64>,           // 已分配槽位（48 位，避免与 Lua 小整数混淆）
    pub getglobal_op: u8,
    pub getglobalstr_op: u8,
    pub setglobal_op: u8,
    pub setglobalstr_op: u8,
}

fn alloc_slot(used: &mut HashSet<u64>, rng: &mut StdRng) -> u64 {
    // 槽位限制为 30 位：f64 精确表示，且启动期混淆的 bxor 路径（32 位）不会截断高位
    loop {
        let v = 0x4000_0000 + (rng.random::<u64>() & 0x3FFF_FFFF);
        if used.insert(v) { return v; }
    }
}

fn scan_setglobal_targets(r: &mut PayloadReader, targets: &mut HashSet<Vec<u8>>, setglobal_op: u8) {
    r.read_string();
    r.read_u32(); r.read_u32();
    r.read_u8(); r.read_u8(); r.read_u8(); r.read_u8();
    let inst_count = r.read_u32();
    let mut raw_insts: Vec<(u8, u8, u32, u32)> = Vec::with_capacity(inst_count as usize);
    for _ in 0..inst_count {
        let op = r.read_u8(); let a = r.read_u8(); let b = r.read_u32(); let c = r.read_u32();
        raw_insts.push((op, a, b, c));
    }
    let const_count = r.read_u32();
    let mut local_consts: Vec<Option<Vec<u8>>> = Vec::with_capacity(const_count as usize);
    for _ in 0..const_count {
        let c_type = r.read_u8();
        match c_type {
            0 => local_consts.push(None),
            1 => { r.read_u8(); local_consts.push(None); }
            2 => { r.read_u64(); local_consts.push(None); }
            3 => { local_consts.push(Some(r.read_string().to_vec())); }
            _ => panic!(),
        }
    }
    for (op, _a, b, _c) in &raw_insts {
        if *op == setglobal_op {
            if let Some(Some(s)) = local_consts.get(*b as usize) {
                targets.insert(s.clone());
            }
        }
    }
    let p_count = r.read_u32();
    for _ in 0..p_count { scan_setglobal_targets(r, targets, setglobal_op); }
    let l_count = r.read_u32();
    r.read_bytes((l_count * 4) as usize);
    let loc_count = r.read_u32();
    for _ in 0..loc_count { r.read_string(); r.read_u32(); r.read_u32(); }
    let upv_count = r.read_u32();
    for _ in 0..upv_count { r.read_string(); }
}

fn scan_global_refs(r: &mut PayloadReader, counts: &mut HashMap<Vec<u8>, u32>, global_ops: [u8; 4]) {
    r.read_string();
    r.read_u32(); r.read_u32();
    r.read_u8(); r.read_u8(); r.read_u8(); r.read_u8();
    let inst_count = r.read_u32();
    let mut raw_insts: Vec<(u8, u8, u32, u32)> = Vec::with_capacity(inst_count as usize);
    for _ in 0..inst_count {
        let op = r.read_u8(); let a = r.read_u8(); let b = r.read_u32(); let c = r.read_u32();
        raw_insts.push((op, a, b, c));
    }
    let const_count = r.read_u32();
    let mut local_consts: Vec<Option<Vec<u8>>> = Vec::with_capacity(const_count as usize);
    for _ in 0..const_count {
        let c_type = r.read_u8();
        match c_type {
            0 => local_consts.push(None),
            1 => { r.read_u8(); local_consts.push(None); }
            2 => { r.read_u64(); local_consts.push(None); }
            3 => { local_consts.push(Some(r.read_string().to_vec())); }
            _ => panic!(),
        }
    }
    for (op, _a, b, _c) in &raw_insts {
        if global_ops.contains(op) {
            if let Some(Some(s)) = local_consts.get(*b as usize) {
                *counts.entry(s.clone()).or_insert(0) += 1;
            }
        }
    }
    let p_count = r.read_u32();
    for _ in 0..p_count { scan_global_refs(r, counts, global_ops); }
    let l_count = r.read_u32();
    r.read_bytes((l_count * 4) as usize);
    let loc_count = r.read_u32();
    for _ in 0..loc_count { r.read_string(); r.read_u32(); r.read_u32(); }
    let upv_count = r.read_u32();
    for _ in 0..upv_count { r.read_string(); }
}

fn rewrite_chunk(r: &mut PayloadReader, w: &mut Vec<u8>, strings: &mut Vec<Vec<u8>>, numbers: &mut Vec<u64>, mapped_opcodes: &[Vec<u32>; 90], builtin_map: &[Vec<u32>], setglobal_targets: &HashSet<Vec<u8>>, global_ctx: &mut GlobalSlotCtx, inverse_opcode_map: &[u8; 90], slot_perm: &[usize], rng: &mut StdRng) {
    write_string(w, r.read_string());
    w.extend_from_slice(&r.read_u32().to_le_bytes().to_vec()); w.extend_from_slice(&r.read_u32().to_le_bytes().to_vec());
    w.push(r.read_u8()); w.push(r.read_u8()); w.push(r.read_u8()); w.push(r.read_u8());
    let inst_count = r.read_u32();
    let mut raw_insts: Vec<(u8, u8, u32, u32)> = Vec::with_capacity(inst_count as usize);
    for _ in 0..inst_count {
        let op = r.read_u8(); let a = r.read_u8(); let b = r.read_u32(); let c = r.read_u32();
        raw_insts.push((op, a, b, c));
    }
    let const_count = r.read_u32();
    let mut local_consts: Vec<(u8, Vec<u8>)> = Vec::with_capacity(const_count as usize);
    for _ in 0..const_count {
        let c_type = r.read_u8();
        match c_type {
            0 => local_consts.push((0, Vec::new())),
            1 => { let b = r.read_u8(); local_consts.push((1, vec![b])); }
            2 => { let n = r.read_u64(); local_consts.push((2, n.to_le_bytes().to_vec())); }
            3 => { let s = r.read_string().to_vec(); local_consts.push((3, s)); }
            _ => panic!(),
        }
    }

    let global_ops = [global_ctx.getglobal_op, global_ctx.getglobalstr_op, global_ctx.setglobal_op, global_ctx.setglobalstr_op];

    const BITRK: u32 = 128;
    let mut referenced_elsewhere: HashSet<usize> = HashSet::new();
    for (op, _a, b, c) in &raw_insts {
        if global_ops.contains(op) { continue; }
        if let Some(real_op) = OpCode::from_u8(inverse_opcode_map[*op as usize]) {
            let is_bx = matches!(real_op.mode(), OpMode::IABx);
            if is_bx {
                if real_op.b_mode() == OpArgMask::K && (*b as usize) < local_consts.len() {
                    referenced_elsewhere.insert(*b as usize);
                }
            } else {
                if real_op.b_mode() == OpArgMask::K && *b >= BITRK {
                    referenced_elsewhere.insert((*b - BITRK) as usize);
                }
                if real_op.c_mode() == OpArgMask::K && *c >= BITRK {
                    referenced_elsewhere.insert((*c - BITRK) as usize);
                }
            }
        }
    }

    let mut builtin_rewrite: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
    let mut omit_const: HashSet<usize> = HashSet::new();
    for (idx, (ctype, bytes)) in local_consts.iter().enumerate() {
        if *ctype == 3 {
            if let Some(slot) = crate::VM::Opcodes::builtins::BUILTIN_NAMES.iter().position(|n| n.as_bytes() == bytes.as_slice()) {
                if !setglobal_targets.contains(bytes) {
                    builtin_rewrite.insert(idx, slot);
                    if !referenced_elsewhere.contains(&idx) {
                        omit_const.insert(idx);
                    }
                }
            }
        }
    }

    // Phase 3：全局槽位化——仅被全局读/写指令引用的字符串常量（且非 builtin 改写）槽位化为数字槽位。
    // 编译期引用计数（预扫描）≥3 的"热"全局分配 2~3 个别名槽位，每次引用随机选取别名，
    // 破解者无法按槽位编号做频次分析。别名以普通 u64 数字常量进 numbers 池（48 位，超出 Lua 小整数范围）。
    let mut global_alias: HashMap<usize, Vec<u64>> = HashMap::new();
    for (idx, (ctype, bytes)) in local_consts.iter().enumerate() {
        if *ctype != 3 { continue; }
        if referenced_elsewhere.contains(&idx) { continue; }
        if builtin_rewrite.contains_key(&idx) { continue; }
        let used_by_global = raw_insts.iter().any(|(op, _a, b, _c)| global_ops.contains(op) && *b as usize == idx);
        if !used_by_global { continue; }
        let name = bytes.clone();
        let refcount = global_ctx.refcounts.get(name.as_slice()).copied().unwrap_or(1);
        let alias_count = if refcount >= 3 { 2 + (refcount % 2) as usize } else { 1 };
        let entry = global_ctx.by_name.entry(name).or_insert_with(|| GlobalSlotInfo { aliases: Vec::new(), refcount });
        while entry.aliases.len() < alias_count {
            entry.aliases.push(alloc_slot(&mut global_ctx.used_slots, rng));
        }
        global_alias.insert(idx, entry.aliases.clone());
        omit_const.insert(idx);
    }
    let mut alias_const_idx: HashMap<u64, u32> = HashMap::new(); // 别名 → 本 chunk 内追加的数字常量索引

    w.extend_from_slice(&inst_count.to_le_bytes());
    for (op, a, b, c) in &raw_insts {
        if global_ops.contains(op) {
            if let Some(aliases) = global_alias.get(&(*b as usize)) {
                let alias = aliases[rng.random_range(0..aliases.len())];
                // 注意：VM 的数字常量池以 IEEE754 双精度位模式存储（不是 u64 整数），
                // 槽位是 48 位整数，可被 f64 精确表示，这里存 f64 比特以便解码后密钥一致
                let new_idx = *alias_const_idx.entry(alias).or_insert_with(|| {
                    local_consts.push((2, (alias as f64).to_le_bytes().to_vec()));
                    (local_consts.len() - 1) as u32
                });
                let is_get = *op == global_ctx.getglobal_op || *op == global_ctx.getglobalstr_op;
                let base = crate::VM::Opcodes::builtins::GLOBAL_SLOT_OP_BASE + if is_get { 0 } else { 1 };
                let vals = builtin_map.get(base).map(|v| v.as_slice()).unwrap_or(&[]);
                let selected_op = if !vals.is_empty() { vals[rng.random_range(0..vals.len())] } else { base as u32 };
                w.extend_from_slice(&selected_op.to_le_bytes()); w.push(*a);
                w.extend_from_slice(&new_idx.to_le_bytes()); w.extend_from_slice(&0u32.to_le_bytes());
                continue;
            }
        }
        if *op == global_ctx.getglobal_op || *op == global_ctx.getglobalstr_op {
            if let Some(slot) = builtin_rewrite.get(&(*b as usize)) {
                let op_index = crate::VM::Opcodes::builtins::BUILTIN_OP_BASE + slot_perm[*slot];
                let mapped_vals = builtin_map.get(op_index).map(|v| v.as_slice()).unwrap_or(&[]);
                let selected_op = if !mapped_vals.is_empty() { mapped_vals[rng.random_range(0..mapped_vals.len())] } else { op_index as u32 };
                w.extend_from_slice(&selected_op.to_le_bytes()); w.push(*a); w.extend_from_slice(&0u32.to_le_bytes()); w.extend_from_slice(&0u32.to_le_bytes());
                continue;
            }
        }
        let mapped_vals = mapped_opcodes.get(*op as usize).map(|v| v.as_slice()).unwrap_or(&[]);
        let selected_op = if !mapped_vals.is_empty() { mapped_vals[rng.random_range(0..mapped_vals.len())] } else { *op as u32 };
        w.extend_from_slice(&selected_op.to_le_bytes()); w.push(*a); w.extend_from_slice(&b.to_le_bytes()); w.extend_from_slice(&c.to_le_bytes());
    }

    let const_count = local_consts.len() as u32;
    w.extend_from_slice(&const_count.to_le_bytes());
    for (idx, (c_type, bytes)) in local_consts.iter().enumerate() {
        if omit_const.contains(&idx) {
            w.push(0);
            continue;
        }
        w.push(*c_type);
        match c_type {
            0 => {}
            1 => w.push(bytes[0]),
            2 => {
                let n = u64::from_le_bytes(bytes.as_slice().try_into().unwrap());
                let pos = numbers.iter().position(|&x| x == n).unwrap_or_else(|| { numbers.push(n); numbers.len() - 1 });
                w.extend_from_slice(&(pos as u32).to_le_bytes());
            }
            3 => {
                let pos = strings.iter().position(|x| x == bytes).unwrap_or_else(|| { strings.push(bytes.clone()); strings.len() - 1 });
                w.extend_from_slice(&(pos as u32).to_le_bytes());
            }
            _ => panic!(),
        }
    }

    let p_count = r.read_u32();
    w.extend_from_slice(&p_count.to_le_bytes());
    for _ in 0..p_count { rewrite_chunk(r, w, strings, numbers, mapped_opcodes, builtin_map, setglobal_targets, global_ctx, inverse_opcode_map, slot_perm, rng); }
    let l_count = r.read_u32();
    w.extend_from_slice(&l_count.to_le_bytes());
    r.read_bytes((l_count * 4) as usize);
    let loc_count = r.read_u32();
    w.extend_from_slice(&loc_count.to_le_bytes());
    for _ in 0..loc_count { write_string(w, r.read_string()); w.extend_from_slice(&r.read_u32().to_le_bytes()); w.extend_from_slice(&r.read_u32().to_le_bytes()); }
    let upv_count = r.read_u32();
    w.extend_from_slice(&upv_count.to_le_bytes());
    for _ in 0..upv_count { write_string(w, r.read_string()); }
}

pub struct Generator { ctx: VmContext }

pub struct GenRng { used: HashSet<String> }

impl GenRng {
    pub fn new(_seed: u64) -> Self { Self { used: HashSet::new() } }
    pub fn next(&mut self) -> u32 { rng().random::<u32>() }
    pub fn range(&mut self, min: usize, max: usize) -> usize { rng().random_range(min..max) }
    pub fn range64(&mut self, min: i64, max: i64) -> i64 { rng().random_range(min..max) }
    pub fn name(&mut self) -> String {
        let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect();
        let keywords = ["and", "break", "do", "else", "elseif", "end", "false", "for", "function", "if", "in", "local", "nil", "not", "or", "repeat", "return", "then", "true", "until", "while"];
        loop {
            let len = self.range(7, 14);
            let s: String = (0..len).map(|_| chars[self.range(0, chars.len())]).collect();
            if !self.used.contains(&s) && !keywords.contains(&s.as_str()) {
                self.used.insert(s.clone());
                crate::VM::Names::register(&s);
                if std::env::var("KRYX_DEBUG_NAMES").is_ok() {
                    eprintln!("[names] gen {:?}", s);
                }
                return s;
            }
        }
    }
    pub fn shuffle<T>(&mut self, slice: &mut [T]) {
        let mut r = rng();
        for i in (1..slice.len()).rev() { slice.swap(i, r.random_range(0..=i)); }
    }
    pub fn format_num(&mut self, val: i64) -> String {
        match self.range(0, 3) {
            0 => { if val < 0 { format!("-0x{:x}", val.unsigned_abs()) } else { format!("0x{:x}", val) } }
            1 => val.to_string(),
            _ => { let lit = crate::VM::numlit::random_binary_literal(val.unsigned_abs()); if val < 0 { format!("-{lit}") } else { lit } }
        }
    }
    pub fn obfuscate_num(&mut self, val: i64, depth: usize, keys: &CipherKeys) -> String {
        if depth == 0 { return self.format_num(val); }
        let style = self.range(0, 10);
        if style < 4 {
            let huge = crate::VM::cf_wrap::big_num(self);
            format!("({}-{})", self.obfuscate_num(val.wrapping_add(huge), depth - 1, keys), self.obfuscate_num(huge, depth - 1, keys))
        } else if style < 7 {
            let mask = crate::VM::cf_wrap::big_num(self);
            format!("{}[{}][{}]({},{})", keys.tbl_p, self.format_num(keys.grp1 as i64), self.format_num(keys.key_bx as i64), self.obfuscate_num(val ^ mask, depth - 1, keys), self.obfuscate_num(mask, depth - 1, keys))
        } else {
            let mask = crate::VM::cf_wrap::big_num(self);
            format!("{}[{}][{}]({},{})", keys.tbl_p, self.format_num(keys.grp1 as i64), self.format_num(keys.key_add as i64), self.obfuscate_num(val.wrapping_sub(mask), depth - 1, keys), self.obfuscate_num(mask, depth - 1, keys))
        }
    }
}

fn build_opcode_tree(handlers: &[(u32, String)], min_idx: usize, max_idx: usize, var_op: &str, keys: &CipherKeys, rng: &mut GenRng) -> String {
    if min_idx == max_idx { return handlers[min_idx].1.clone(); }
    let mid = (min_idx + max_idx) / 2;
    let left = build_opcode_tree(handlers, min_idx, mid, var_op, keys, rng);
    let right = build_opcode_tree(handlers, mid + 1, max_idx, var_op, keys, rng);
    let direction = rng.range(0, 2) == 0;
    if direction {
        let cond = ControlFlowBuilder::generate_opaque_predicate(handlers[mid].0 as i64, var_op, "<=", keys, rng);
        format!("if {} then {} else {} end ", cond, left, right)
    } else {
        let cond = ControlFlowBuilder::generate_opaque_predicate(handlers[mid].0 as i64, var_op, ">", keys, rng);
        format!("if {} then {} else {} end ", cond, right, left)
    }
}


mod impl_generator;
mod data_fields;
// pub：`decoder.rs` / `stub_generator.rs` 生成 isNative 判定代码时也要用
// 这里的 `escaped_literal_q`，把 `"lo".."adstring"`、`"de".."bug"` 这类
// 敏感词字面量渲染成与报错改写同款的多转义混用形态。
pub mod entry_wrap;
