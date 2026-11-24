// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use std::time::SystemTime;
use rand::{rngs::StdRng, Rng, SeedableRng, random};

use crate::VM::cf_wrap;
use crate::VM::Control_Flow::Control_flow::ControlFlowBuilder;
use crate::VM::VM_Backend::Generator::GenRng;
use crate::VM::VM_Backend::Sandbox::generate_sandbox;

struct SimpleRng {
    rng: StdRng,
}

impl SimpleRng {
    fn new(seed: u32) -> Self {
        let seed_val = if seed == 0 {
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0)
        } else {
            let t = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            t ^ (seed as u64)
        };
        
        Self {
            rng: StdRng::seed_from_u64(seed_val),
        }
    }

    fn next(&mut self) -> u32 {
        self.rng.random()
    }

    fn next_range(&mut self, min: usize, max: usize) -> usize {
        if min >= max { return min; }
        self.rng.random_range(min..max)
    }
}

#[derive(Clone, Copy)]
enum Step {
    Raw,
    Link { stride: u16, span: u16 },
}

pub struct Packer;

impl Packer {
    pub fn pack(input: &[u8], vm_rng: &mut GenRng) -> (String, String, String, usize) {
        let seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u32)
            .unwrap_or(0xDEADBEEF);
        let mut rng = SimpleRng::new(seed);
        let mut keys = Vec::new();
        for _ in 0..16 {
            keys.push((rng.next() & 0xFF) as u8);
        }
        let sandbox = generate_sandbox("kryvex");
        let compressed_sb = Self::encode_stream(sandbox.payload.as_bytes());
        let encrypted_sb = Self::xor_stream_with_keys(&compressed_sb, &keys);
        let b85_sb = Self::base85_encode_mixed(&encrypted_sb);

        let compressed_main = Self::encode_stream(input);
        let encrypted_main = Self::xor_stream_with_keys(&compressed_main, &keys);
        let b85_main = Self::base85_encode_mixed(&encrypted_main);

        let lua_payload = format!("{}~{}", b85_sb, b85_main);
        // 长括号 padding 选择：载荷字母表为 0x21..0x75（含 ']'(0x5D) 与 '='(0x3D)），
        // 可能含 `]={k}]` 破坏长括号；选最小 k≥1 使终止符不出现，形态随载荷自适应。
        let mut pad = 1usize;
        while lua_payload.contains(&format!("]{}]", "=".repeat(pad))) {
            pad += 1;
        }

        let (decoder_script, entry_func) = Self::build_decoder(&keys, vm_rng);
        (lua_payload, decoder_script, entry_func, pad)
    }

    fn encode_stream(input: &[u8]) -> Vec<u8> {
        let len = input.len();
        if len == 0 {
            return Vec::new();
        }

        let mut costs = vec![u32::MAX; len + 1];
        let mut links = vec![Step::Raw; len + 1];
        costs[0] = 0;

        for i in 0..len {
            if costs[i] == u32::MAX {
                continue;
            }

            let cost_raw = costs[i] + 9;
            if cost_raw < costs[i + 1] {
                costs[i + 1] = cost_raw;
                links[i + 1] = Step::Raw;
            }

            let max_search = if i > 65535 { i - 65535 } else { 0 };
            let max_span = std::cmp::min(258, len - i);

            let mut optimal_strides = vec![0u16; max_span + 1];
            let mut peak_span = 0;

            for start in max_search..i {
                if peak_span < max_span && input[start + peak_span] == input[i + peak_span] {
                    let mut current_span = 0;
                    while current_span < max_span && input[start + current_span] == input[i + current_span] {
                        current_span += 1;
                    }
                    if current_span > peak_span {
                        for l in (peak_span + 1)..=current_span {
                            optimal_strides[l] = (i - start) as u16;
                        }
                        peak_span = current_span;
                    }
                }
            }

            for span_l in 3..=peak_span {
                let cost_link = costs[i] + 25;
                let next_pos = i + span_l;
                if cost_link < costs[next_pos] {
                    costs[next_pos] = cost_link;
                    links[next_pos] = Step::Link {
                        stride: optimal_strides[span_l],
                        span: span_l as u16,
                    };
                }
            }
        }

        let mut route = Vec::new();
        let mut cursor = len;
        while cursor > 0 {
            match links[cursor] {
                Step::Raw => {
                    route.push(Step::Raw);
                    cursor -= 1;
                }
                Step::Link { stride, span } => {
                    route.push(Step::Link { stride, span });
                    cursor -= span as usize;
                }
            }
        }
        route.reverse();

        let mut output = Vec::new();
        let mut route_head = 0;
        let route_len = route.len();
        let mut read_head = 0;

        while route_head < route_len {
            let mut header = 0u8;
            let mut payload_part = Vec::new();

            for bit in 0..8 {
                if route_head >= route_len {
                    break;
                }

                match route[route_head] {
                    Step::Raw => {
                        header |= 1 << bit;
                        payload_part.push(input[read_head]);
                        read_head += 1;
                    }
                    Step::Link { stride, span } => {
                        let b1 = (stride >> 8) as u8;
                        let b2 = (stride & 0xFF) as u8;
                        let b3 = (span - 3) as u8;
                        payload_part.push(b1);
                        payload_part.push(b2);
                        payload_part.push(b3);
                        read_head += span as usize;
                    }
                }
                route_head += 1;
            }

            output.push(header);
            output.extend_from_slice(&payload_part);
        }

        output
    }

    fn xor_stream_with_keys(input: &[u8], keys: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        for (i, &b) in input.iter().enumerate() {
            output.push(b ^ keys[i % 16]);
        }
        output
    }

    /// sample2 风格的自研混合进制编码（Ascii85 形态）：
    /// 每 4 字节 -> 5 个字符，字符 = 0x21 + 数字（'!'..'u'，跳过容器不允许的字符并不可能，
    /// 因为 0x21..0x75 全部可直接置于长括号内；长括号 padding 由 pack() 自适应选择）。
    /// 解码侧直接 byte - 0x21 做混合进制还原：v = b1 + b2*85 + b3*85^2 + b4*85^3 + b5*85^4，
    /// 输出小端字节序。余数：3 字节 -> 4 字符、2 字节 -> 3 字符、1 字节 -> 2 字符。
    fn base85_encode_mixed(input: &[u8]) -> String {
        let mut encoded = String::with_capacity(input.len() / 4 * 5 + 8);
        let mut i = 0;
        while i + 4 <= input.len() {
            let v = ((input[i] as u32) << 24)
                | ((input[i + 1] as u32) << 16)
                | ((input[i + 2] as u32) << 8)
                | (input[i + 3] as u32);
            // 小端数字序（低权重先行）：c1=v%85, c2=(v/85)%85, ..., c5=v/85^4
            let mut rem = v;
            for _ in 0..5 {
                encoded.push((0x21 + (rem % 85) as u8) as char);
                rem /= 85;
            }
            i += 4;
        }
        let rem = input.len() - i;
        if rem == 3 {
            let v = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
            let mut rem2 = v;
            for _ in 0..4 {
                encoded.push((0x21 + (rem2 % 85) as u8) as char);
                rem2 /= 85;
            }
        } else if rem == 2 {
            let v = ((input[i] as u32) << 8) | (input[i + 1] as u32);
            let mut rem2 = v;
            for _ in 0..3 {
                encoded.push((0x21 + (rem2 % 85) as u8) as char);
                rem2 /= 85;
            }
        } else if rem == 1 {
            let v = input[i] as u32;
            encoded.push((0x21 + (v % 85) as u8) as char);
            encoded.push((0x21 + (v / 85) as u8) as char);
        }
        encoded
    }

    fn build_decoder(keys: &[u8], rng: &mut GenRng) -> (String, String) {
        // entry 常量：严格降序、两两间距 ≥100（a>b>c>d），供 cf_wrap 判断条件推算真假
        let vd = rng.range(1, 1500) as i64;
        let vc = vd + rng.range(100, 1500) as i64;
        let vb = vc + rng.range(100, 1500) as i64;
        let va = vb + rng.range(100, 1500) as i64;
        cf_wrap::set_constants(va, vb, vc, vd);
        let f_entry = rng.name();
        let v_data = rng.name();

        let m_bxor = rng.name();
        let m_next = rng.name();
        let m_init_map = rng.name();
        let m_init_insts = rng.name();
        let m_init_handlers = rng.name();
        let m_run = rng.name();
        let m_main = rng.name();

        // 壳字段：全部内建函数/位运算兜底作为 return ({...}) 壳的字段携带，
        // 正文只通过壳（q）引用，不直接出现 unpack/math.floor 等全局引用。
        let k_un = rng.name();
        let k_ch = rng.name();
        let k_by = rng.name();
        let k_fl = rng.name();
        let k_ins = rng.name();
        let k_cat = rng.name();
        let k_rem = rng.name();
        let k_rev = rng.name();
        let k_lf = rng.name();
        let k_gm = rng.name();

        // 内部状态表字段名：全部随机化。
        // compressor 的重命名门禁（len>4 且非保留成员）会跳过 len<=4 的短字段名
        // 与内建库同名字段，产物中会出现语义变量（map/idx/len/...），因此在模板层
        // 先把这些内部字段名全部替换为随机名；词法扫描在 format! 之后统一做整词替换。
        let f_data = rng.name();
        let f_pc = rng.name();
        let f_idx = rng.name();
        let f_kidx = rng.name();
        let f_buf = rng.name();
        let f_res = rng.name();
        let f_bc = rng.name();
        let f_f = rng.name();
        let f_p1 = rng.name();
        let f_p2 = rng.name();
        let f_w = rng.name();
        let f_u = rng.name();
        let f_ptr = rng.name();
        let f_k = rng.name();
        let f_memo = rng.name();
        let f_len = rng.name();
        let f_insts = rng.name();
        let f_tamper = rng.name();
        let f_handlers = rng.name();
        let f_r_flg = rng.name();
        let f_r_vals = rng.name();
        let f_r_len = rng.name();
        let f_tail_flg = rng.name();
        let f_unpack = rng.name();
        let f_char = rng.name();
        let f_byte = rng.name();
        let f_floor = rng.name();
        let f_insert = rng.name();
        let f_concat = rng.name();
        let f_remove = rng.name();
        let f_reverse = rng.name();
        let sb_chunk = rng.name();

        // ===== 第 3/5 类包装：内建别名 + 样板填充函数（对齐 sample2 的壳外观）=====
        // 字段名用 rng.name() 生成，收尾时随其它壳字段一起压成 1~2 字符短名。
        let mut pad_fields: Vec<String> = Vec::new();
        {
            // 内建别名 6~11 个（sample2 有 20 个）
            for _ in 0..rng.range(6, 12) {
                let nm = rng.name();
                pad_fields.push(crate::VM::shell_pad::builtin_alias(rng, &nm));
            }
            // 库整体别名 1~4 个（`i=table`、`r=buffer`、`u=unpack`、`Z=error`）
            for _ in 0..rng.range(1, 5) {
                let nm = rng.name();
                pad_fields.push(crate::VM::shell_pad::lib_alias(rng, &nm));
            }
            // 样板填充函数 5~9 个（空函数 / 恒等 / 只读只写槽位 / 变参空转 / 槽位清空）
            for _ in 0..rng.range(5, 10) {
                let nm = rng.name();
                pad_fields.push(crate::VM::shell_pad::pad_function(rng, &nm));
            }
        }

        let op_state0 = rng.range(100, 200);
        let op_state1 = rng.range(201, 300);
        let op_state2 = rng.range(301, 400);
        let op_state3 = rng.range(401, 500);
        let op_state4 = rng.range(501, 600);
        let op_state5 = rng.range(601, 700);
        let op_state6 = rng.range(701, 800);
        let op_state7 = rng.range(801, 900);
        let op_state8 = rng.range(901, 1000);
        let op_state9 = rng.range(1001, 1100);

        let mut pcs: Vec<usize> = (1..=10).collect();
        for i in (1..10).rev() {
            let j = rng.range(0, i + 1);
            pcs.swap(i, j);
        }
        let pc_state0 = pcs[0];
        let pc_state1 = pcs[1];
        let pc_state2 = pcs[2];
        let pc_state3 = pcs[3];
        let pc_state4 = pcs[4];
        let pc_state5 = pcs[5];
        let pc_state6 = pcs[6];
        let pc_state7 = pcs[7];
        let pc_state8 = pcs[8];
        let pc_state9 = pcs[9];

        let tamper_val = rng.range(10, 50);

        let mut insts_init = Vec::new();
        for (pc, op) in [
            (pc_state0, op_state0), (pc_state1, op_state1), (pc_state2, op_state2), (pc_state3, op_state3),
            (pc_state4, op_state4), (pc_state5, op_state5), (pc_state6, op_state6), (pc_state7, op_state7),
            (pc_state8, op_state8), (pc_state9, op_state9),
        ] {
            insts_init.push(cf_wrap::wrap_stmt(&format!("s.insts[{}]={{{}}};", pc, op), rng));
        }

        let n_insts = insts_init.len();
        let mut insts_states: Vec<usize> = (1..=n_insts+1).collect();
        for i in (1..insts_states.len()).rev() {
            let j = rng.range(0, i + 1);
            insts_states.swap(i, j);
        }
        
        let mut init_insts_loop = String::new();
        init_insts_loop.push_str(&format!("st={};while {} do ", insts_states[0], cf_wrap::const_true(rng)));
        for (i, inst) in insts_init.iter().enumerate() {
            let curr_st = insts_states[i];
            let next_st = insts_states[i+1];
            // 每个状态分支用独立的 if...end，避免 elseif 链中间插入 st=Y; 语句导致语法错误
            init_insts_loop.push_str(&format!("if st=={} then {}st={}; end;", curr_st, inst, next_st));
        }
        init_insts_loop.push_str("break; end;");

        // 每个 handler 的所有功能语句都被包进随机控制流（cf_wrap）
        let mut handlers_init = Vec::new();
        handlers_init.push(format!(
            "s.handlers[{}+{}] = function(inst) {} end;",
            op_state0, tamper_val,
            cf_wrap::wrap_all(&[
                "s.bc = 8;".into(),
                "s.res = {};".into(),
                format!("s.pc = {};", pc_state1),
            ], rng)
        ));
        handlers_init.push(format!(
            "s.handlers[{}+{}] = function(inst) if s.bc > 7 then {} else {} end end;",
            op_state1, tamper_val,
            cf_wrap::wrap_all(&[format!("s.pc = {};", pc_state2)], rng),
            cf_wrap::wrap_all(&[format!("s.pc = {};", pc_state3)], rng)
        ));
        handlers_init.push(format!(
            "s.handlers[{}+{}] = function(inst) {} if not s.f then {} return end; {} {} end;",
            op_state2, tamper_val,
            cf_wrap::wrap_all(&[format!("s.f = q:{}(s);", m_next)], rng),
            cf_wrap::wrap_all(&[
                "s.r_flg = true;".into(),
                "s.r_vals = {s.concat(s.res)};".into(),
                "s.r_len = 1;".into(),
            ], rng),
            cf_wrap::wrap_all(&["s.bc = 0;".into()], rng),
            cf_wrap::wrap_all(&[format!("s.pc = {};", pc_state3)], rng)
        ));
        handlers_init.push(format!(
            "s.handlers[{}+{}] = function(inst) if (s.f % 2) == 1 then {} else {} end end;",
            op_state3, tamper_val,
            cf_wrap::wrap_all(&[format!("s.pc = {};", pc_state4)], rng),
            cf_wrap::wrap_all(&[format!("s.pc = {};", pc_state5)], rng)
        ));
        handlers_init.push(format!(
            "s.handlers[{}+{}] = function(inst) {} if not s.u then {} return end; {} {} end;",
            op_state4, tamper_val,
            cf_wrap::wrap_all(&[format!("s.u = q:{}(s);", m_next)], rng),
            cf_wrap::wrap_all(&[
                "s.r_flg = true;".into(),
                "s.r_vals = {s.concat(s.res)};".into(),
                "s.r_len = 1;".into(),
            ], rng),
            cf_wrap::wrap_all(&["s.res[#s.res+1] = s.char(s.u);".into()], rng),
            cf_wrap::wrap_all(&[format!("s.pc = {};", pc_state9)], rng)
        ));
        handlers_init.push(format!(
            "s.handlers[{}+{}] = function(inst) {} if not s.p1 then {} return end; {} end;",
            op_state5, tamper_val,
            cf_wrap::wrap_all(&[format!("s.p1 = q:{}(s);", m_next)], rng),
            cf_wrap::wrap_all(&[
                "s.r_flg = true;".into(),
                "s.r_vals = {s.concat(s.res)};".into(),
                "s.r_len = 1;".into(),
            ], rng),
            cf_wrap::wrap_all(&[format!("s.pc = {};", pc_state6)], rng)
        ));
        handlers_init.push(format!(
            "s.handlers[{}+{}] = function(inst) {} if not s.p2 then {} return end; {} end;",
            op_state6, tamper_val,
            cf_wrap::wrap_all(&[format!("s.p2 = q:{}(s);", m_next)], rng),
            cf_wrap::wrap_all(&[
                "s.r_flg = true;".into(),
                "s.r_vals = {s.concat(s.res)};".into(),
                "s.r_len = 1;".into(),
            ], rng),
            cf_wrap::wrap_all(&[format!("s.pc = {};", pc_state7)], rng)
        ));
        handlers_init.push(format!(
            "s.handlers[{}+{}] = function(inst) {} if not s.w then {} return end; {} end;",
            op_state7, tamper_val,
            cf_wrap::wrap_all(&[format!("s.w = q:{}(s);", m_next)], rng),
            cf_wrap::wrap_all(&[
                "s.r_flg = true;".into(),
                "s.r_vals = {s.concat(s.res)};".into(),
                "s.r_len = 1;".into(),
            ], rng),
            cf_wrap::wrap_all(&[format!("s.pc = {};", pc_state8)], rng)
        ));
        handlers_init.push(format!(
            "s.handlers[{}+{}] = function(inst, iter) {} {} while {} do if iter >= s.w + 3 then break end; {} {} end; {} end;",
            op_state8, tamper_val,
            cf_wrap::wrap_all(&["s.ptr = #s.res - (s.p1 * 256 + s.p2) + 1;".into()], rng),
            cf_wrap::wrap_all(&["iter = 0;".into()], rng),
            cf_wrap::const_true(rng),
            cf_wrap::wrap_all(&["s.res[#s.res+1] = s.res[s.ptr + iter];".into()], rng),
            cf_wrap::wrap_all(&["iter = iter + 1;".into()], rng),
            cf_wrap::wrap_all(&[format!("s.pc = {};", pc_state9)], rng)
        ));
        handlers_init.push(format!(
            "s.handlers[{}+{}] = function(inst) {} {} {} end;",
            op_state9, tamper_val,
            cf_wrap::wrap_all(&["s.f = s.floor(s.f / 2);".into()], rng),
            cf_wrap::wrap_all(&["s.bc = s.bc + 1;".into()], rng),
            cf_wrap::wrap_all(&[format!("s.pc = {};", pc_state1)], rng)
        ));

        let n_handlers = handlers_init.len();
        let mut handlers_states: Vec<usize> = (1..=n_handlers+1).collect();
        for i in (1..handlers_states.len()).rev() {
            let j = rng.range(0, i + 1);
            handlers_states.swap(i, j);
        }
        
        let mut init_handlers_loop = String::new();
        init_handlers_loop.push_str(&format!("st={};while {} do ", handlers_states[0], cf_wrap::const_true(rng)));
        for (i, h) in handlers_init.iter().enumerate() {
            let curr_st = handlers_states[i];
            let next_st = handlers_states[i+1];
            // 每个状态分支用独立的 if...end，避免 elseif 链中间插入 st=Y; 语句导致语法错误
            init_handlers_loop.push_str(&format!("if st=={} then {}st={}; end;", curr_st, h, next_st));
        }
        init_handlers_loop.push_str("break; end;");

        // 数字池只跟控制流的规模挂钩：整个解码器只用这 11 个数，其余全部由计算得出。
        // 必须在生成 router / 各 handler 之前重置一次，再在 router 生成后**再**重置，
        // 这样控制流内部的复用池也是同一套固定数字（用户要求：同一批数字反复用）。
        cf_wrap::reset_numbers(rng);
        cf_wrap::set_big_pool(&mut *rng);
        let router_code = ControlFlowBuilder::build_fast_router(
            "s.pc", "s.insts", "inst", "s.handlers", "s.r_flg", "s.r_vals", "s.r_len", "s.tamper", "s.tail_flg", &format!("s.{}", f_unpack), rng
        );

        cf_wrap::reset_numbers(rng);
        let num_key_parts = rng.range(3, 7);
        let mut key_boundaries = Vec::new();
        for _ in 0..num_key_parts.saturating_sub(1) {
            key_boundaries.push(rng.range(1, keys.len()));
        }
        key_boundaries.sort_unstable();
        key_boundaries.dedup();
        let mut kb = vec![0];
        kb.extend(key_boundaries);
        if *kb.last().unwrap() != keys.len() {
            kb.push(keys.len());
        }

        let mut key_parts_exprs = Vec::new();
        let num_actual_key_parts = kb.len() - 1;
        for i in 0..num_actual_key_parts {
            let start = kb[i];
            let end = kb[i + 1];
            let part_bytes = &keys[start..end];
            let method = rng.range(0, 2);
            let expr = match method {
                0 => {
                    let mut char_args = String::new();
                    for (idx, b) in part_bytes.iter().enumerate() {
                        if idx > 0 { char_args.push(','); }
                        char_args.push_str(&b.to_string());
                    }
                    format!("s.char({})", char_args)
                }
                _ => {
                    let mut escaped = String::new();
                    for b in part_bytes {
                        escaped.push_str(&format!("\\{:03}", b));
                    }
                    format!("\"{}\"", escaped)
                }
            };
            key_parts_exprs.push(expr);
        }
        let combined_key_expr = key_parts_exprs.join(",");

        // ===== 解码器函数体：所有功能语句都包进随机控制流（cf_wrap） =====
        let mut sb = String::with_capacity(32768);
        // 外壳对象真名：`local {shell} = ({...})`，前导区里能直接引用。
        // 绝不能用 `q` —— 解码器里大量函数形参就叫 `q`（`function(q, s, ...)`）。
        let shell_obj = rng.name();
        sb.push_str(&format!("\nlocal function {f_entry}({v_data})\n"));
        sb.push_str("    local _;\n");
        sb.push_str(&format!("    local {} = ({{\n", shell_obj));
        // ---------- m_bxor ----------
        sb.push_str(&format!("        {m_bxor} = function(q, s, a_, b_, ra, rb, p, c_, rra, rrb, k_bxor, t_cache, k_cache)\n"));
        sb.push_str(&format!("            {}\n", cf_wrap::wrap_stmt("k_bxor = a_ * 256 + b_;", rng)));
        // ── 第 10 类：缓存槽位记忆化（sample2 的招牌形态）──
        // 原来的写法是两条裸语句：`_=s.memo[k];if _ then return _ end;`
        // 现在整体换成分层形态，既保留 sample2 的观感，又严格合法：
        //
        //   1) 命中就提前返回（`return` 必须是块的**最后一条语句**，所以单独包一层）：
        //        <seed>;if not((memo)[k]==nil) then return (memo)[k] end
        //   2) 未命中：直接算 `c_ = a_*256+b_`，不走缓存（保证与原实现逐位一致）
        //   3) 散场前把结果回填进缓存槽，并顺手清掉一处旧槽（sample2 的 `v[k]=nil` 写法）：
        //        <seed>;if (memo)[k]==nil then (memo)[k]=c_ else (memo)[k]=0x<旧槽> end;
        //        (memo)[0X<随机>]=nil;
        {
            // 命中判断：`not((memo)[k]==nil)` 这种双重否定 + 比较混用
            // sample2 的招牌写法：先把槽位取到临时变量，再用 `if not(not t)` 判断，
            // 命中就直接 return（`return` 必须是块尾，所以整句自成一块）。
            let t_slot = rng.name();
            sb.push_str(&format!(
                "            {sd};{t}=s.{memo}[k_bxor];if {g} then return {t} end;\n",
                sd = cf_wrap::seed_pub(rng).0,
                t = t_slot,
                memo = f_memo,
                g = match rng.range(0, 3) {
                    0 => format!("not(({t_slot})==nil)"),
                    1 => format!("not(not {t_slot})"),
                    _ => format!("{t_slot}~=(nil)"),
                },
            ));
            // 未命中的真实计算 + 回填（回填写在 while 之后，见 m_bxor 结尾）
            sb.push_str(&format!("            {}\n", cf_wrap::wrap_stmt("c_ = a_ * 256 + b_;", rng)));
        }
        sb.push_str(&format!("            {}\n", cf_wrap::wrap_stmt("ra, rb, p, c_ = a_, b_, 1, 0;", rng)));
        sb.push_str(&format!("            while {} do\n", cf_wrap::const_true(rng)));
        sb.push_str("                if ra > 0 or rb > 0 then\n");
        sb.push_str(&format!("                    {}\n", cf_wrap::wrap_stmt("rra, rrb = ra % 2, rb % 2;", rng)));
        sb.push_str("                    if rra ~= rrb then\n");
        sb.push_str(&format!("                        {}\n", cf_wrap::wrap_stmt("c_ = c_ + p;", rng)));
        sb.push_str("                    end\n");
        sb.push_str(&format!("                    {}\n", cf_wrap::wrap_stmt("ra, rb, p = s.floor((ra - rra) / 2), s.floor((rb - rrb) / 2), p * 2;", rng)));
        sb.push_str("                else break end;\n            end;\n");
        // 缓存槽回填：`c_` 此刻才是真正的异或结果（循环里累积的那个），
        // 写错位置（写成键 k_bxor）会让第二次同键调用直接返回错误值。
        sb.push_str(&format!(
            "            {sd};if s.{memo}[k_bxor]==nil then s.{memo}[k_bxor]=c_;else s.{memo}[k_bxor]=(0x{os:X}-0x{os:X}) end;do s.{memo}[0x{ns:X}]=nil;end\n",
            sd = cf_wrap::seed_pub(rng).0,
            memo = f_memo,
            os = rng.range(0x100, 0x7000),
            ns = rng.range(0x10000, 0x6FFFF),
        ));
        // 第二个缓存槽：写一个「键→结果」之外的派生量（`c_ + 常量`），
        // 用 sample2 那种 `if not(not m[k]) then … else … end` 的二段式，
        // 但它是纯装饰：只在从未写过的槽位上写一次，之后不再读。
        {
            let slot2 = rng.range(0x10000, 0x6FFFF);
            let bump = rng.range(1, 0x40);
            sb.push_str(&format!(
                // 注意：压缩器会去掉分号，`X=c_+25;(s.m)[k]=(X)` 会粘成
                // `X=c_+25 (s.m)[k]=(X)` 而报语法错。所以赋值一律包进 `do … end`。
                "            {sd};if not(not s.{memo}[0x{s2:X}]) then {tc}=s.{memo}[0x{s2:X}];else {tc}=c_+{bp};do s.{memo}[0x{s2:X}]=({tc});end;end;\n",
                sd = cf_wrap::seed_pub(rng).0,
                memo = f_memo,
                s2 = slot2,
                tc = "t_cache",
                bp = bump,
            ));
        }
        sb.push_str("            local function hg(dr, ...) repeat return c_ or nil until dr end;local df=hg(true)\n");
        sb.push_str("            return df;\n        end,\n");
        // ---------- m_next ----------
        sb.push_str(&format!("        {m_next} = function(q, s, r, c_, e, v, x, y, z, i, d_, b_, k, B, F)\n"));
        sb.push_str(&format!("    {}\n", cf_wrap::wrap_stmt("B, F = s.byte, s.floor;", rng)));
        sb.push_str(&format!("    {}\n", cf_wrap::wrap_stmt("i, d_, b_, k = s.idx, s.data, s.buf, s.kidx;", rng)));
        sb.push_str("    if #b_ > 0 then\n");
        sb.push_str(&format!("        {}\n", cf_wrap::wrap_stmt("r = s.remove(b_, 1);", rng)));
        sb.push_str(&format!("        {}\n", cf_wrap::wrap_stmt(&format!("c_ = q:{m_bxor}(s, r, s.k[k + 1]);"), rng)));
        sb.push_str(&format!("        {}\n", cf_wrap::wrap_stmt("s.kidx = (k + 1) % 16;", rng)));
        sb.push_str("        return c_;\n    end;\n");
        sb.push_str("    if i > s.len then return nil end;\n");
        sb.push_str(&format!("    {}\n", cf_wrap::wrap_stmt("e = s.len - i + 1;", rng)));
        sb.push_str("    if e >= 5 then\n");
        sb.push_str(&format!("        {}\n", cf_wrap::wrap_stmt("v = (B(d_, i)-33) + (B(d_, i+1)-33)*85 + (B(d_, i+2)-33)*7225 + (B(d_, i+3)-33)*614125 + (B(d_, i+4)-33)*52200625;", rng)));
        sb.push_str(&format!("        {}\n", cf_wrap::wrap_stmt("z, y, x = v % 256, F(v / 256) % 256, F(v / 65536) % 256;", rng)));
        sb.push_str(&format!("        {}\n", cf_wrap::wrap_stmt("v = F(v / 16777216);", rng)));
        sb.push_str(&format!("        {}\n", cf_wrap::wrap_stmt("b_[1], b_[2], b_[3], b_[4] = v, x, y, z;", rng)));
        sb.push_str(&format!("        {}\n", cf_wrap::wrap_stmt("i = i + 5;", rng)));
        sb.push_str("    elseif e >= 4 then\n");
        sb.push_str(&format!("        {}\n", cf_wrap::wrap_stmt("v = (B(d_, i)-33) + (B(d_, i+1)-33)*85 + (B(d_, i+2)-33)*7225 + (B(d_, i+3)-33)*614125;", rng)));
        sb.push_str(&format!("        {}\n", cf_wrap::wrap_stmt("y, x = v % 256, F(v / 256) % 256;", rng)));
        sb.push_str(&format!("        {}\n", cf_wrap::wrap_stmt("v = F(v / 65536);", rng)));
        sb.push_str(&format!("        {}\n", cf_wrap::wrap_stmt("b_[1], b_[2], b_[3] = v, x, y;", rng)));
        sb.push_str(&format!("        {}\n", cf_wrap::wrap_stmt("i = i + 4;", rng)));
        sb.push_str("    elseif e >= 3 then\n");
        sb.push_str(&format!("        {}\n", cf_wrap::wrap_stmt("v = (B(d_, i)-33) + (B(d_, i+1)-33)*85 + (B(d_, i+2)-33)*7225;", rng)));
        sb.push_str(&format!("        {}\n", cf_wrap::wrap_stmt("x = v % 256;", rng)));
        sb.push_str(&format!("        {}\n", cf_wrap::wrap_stmt("v = F(v / 256);", rng)));
        sb.push_str(&format!("        {}\n", cf_wrap::wrap_stmt("b_[1], b_[2] = v, x;", rng)));
        sb.push_str(&format!("        {}\n", cf_wrap::wrap_stmt("i = i + 3;", rng)));
        sb.push_str("    elseif e >= 2 then\n");
        sb.push_str(&format!("        {}\n", cf_wrap::wrap_stmt("v = (B(d_, i)-33) + (B(d_, i+1)-33)*85;", rng)));
        sb.push_str(&format!("        {}\n", cf_wrap::wrap_stmt("b_[1] = v;", rng)));
        sb.push_str(&format!("        {}\n", cf_wrap::wrap_stmt("i = i + 2;", rng)));
        sb.push_str("    else\n");
        sb.push_str(&format!("        {}\n", cf_wrap::wrap_stmt("i = i + 1;", rng)));
        sb.push_str("    end;\n");
        sb.push_str(&format!("    {}\n", cf_wrap::wrap_stmt("s.idx = i;", rng)));
        sb.push_str(&format!("    {}\n", cf_wrap::wrap_stmt(&format!("return q:{m_next}(s);"), rng)));
        sb.push_str("        end,\n");
        // ---------- m_init_map ----------
        sb.push_str(&format!("        {m_init_map} = function(q, s, parts, i, kparts, kstr)\n"));
        sb.push_str(&format!("            {}\n", cf_wrap::wrap_stmt(&format!("kparts = {{{combined_key_expr}}};"), rng)));
        sb.push_str(&format!("            {}\n", cf_wrap::wrap_stmt("kstr = \"\";", rng)));
        sb.push_str(&format!("            {}\n", cf_wrap::wrap_stmt("i = 1;", rng)));
        sb.push_str(&format!("            while {} do\n", cf_wrap::const_true(rng)));
        sb.push_str(&format!("                if i > {num_actual_key_parts} then break end;\n"));
        sb.push_str(&format!("                {}\n", cf_wrap::wrap_stmt("kstr = kstr .. kparts[i];", rng)));
        sb.push_str(&format!("                {}\n", cf_wrap::wrap_stmt("i = i + 1;", rng)));
        sb.push_str("            end;\n");
        sb.push_str(&format!("            {}\n", cf_wrap::wrap_stmt("i = 1;", rng)));
        sb.push_str(&format!("            while {} do\n", cf_wrap::const_true(rng)));
        sb.push_str("                if i > #kstr then break end;\n");
        sb.push_str(&format!("                {}\n", cf_wrap::wrap_stmt("s.k[i] = s.byte(kstr, i);", rng)));
        sb.push_str(&format!("                {}\n", cf_wrap::wrap_stmt("i = i + 1;", rng)));
        sb.push_str("            end\n        end,\n");
        // ---------- m_init_insts / m_init_handlers ----------
        sb.push_str(&format!("        {m_init_insts} = function(q, s, st)\n            {init_insts_loop}        end,\n"));
        sb.push_str(&format!("        {m_init_handlers} = function(q, s, st)\n            {init_handlers_loop}        end,\n"));
        // ---------- m_run ----------
        sb.push_str(&format!("        {m_run} = function(q, s)\n            {}\n        end,\n", cf_wrap::wrap_stmt(&router_code, rng)));
        // ---------- m_main ----------
        sb.push_str(&format!("        {m_main} = function(q, data)\n"));
        sb.push_str(&format!("            local insert, load_func, gmatch = q.{k_ins}, q.{k_lf}, q.{k_gm};\n"));
        sb.push_str("            return (function(s)\n");
        sb.push_str(&format!("                {}\n", cf_wrap::wrap_stmt(&format!("q:{m_init_map}(s);"), rng)));
        sb.push_str(&format!("                {}\n", cf_wrap::wrap_stmt(&format!("q:{m_init_insts}(s);"), rng)));
        sb.push_str(&format!("                {}\n", cf_wrap::wrap_stmt(&format!("q:{m_init_handlers}(s);"), rng)));
        sb.push_str("                local parts = {}\n");
        sb.push_str("                for part in gmatch(s.data, \"[^~]+\") do\n");
        sb.push_str(&format!("                    {}\n", cf_wrap::wrap_stmt("insert(parts, part)", rng)));
        sb.push_str("                end\n");
        sb.push_str(&format!("                {}\n", cf_wrap::wrap_stmt("s.data = parts[1];", rng)));
        sb.push_str(&format!("                {}\n", cf_wrap::wrap_stmt("s.len = #s.data;", rng)));
        sb.push_str("                local sb_expr = false;\n");
        sb.push_str(&format!("                {}\n", cf_wrap::wrap_stmt(&format!("sb_expr = q:{m_run}(s);"), rng)));
        sb.push_str("                local get_sb_code = false;\n");
        sb.push_str(&format!("                {}\n", cf_wrap::wrap_stmt("get_sb_code = load_func(\"return \" .. sb_expr);", rng)));
        sb.push_str("                local sb_code = false;\n");
        sb.push_str(&format!("                {}\n", cf_wrap::wrap_stmt("sb_code = get_sb_code and get_sb_code() or \"\";", rng)));
        sb.push_str("                local env_maker_chunk = false;\n");
        sb.push_str(&format!("                {}\n", cf_wrap::wrap_stmt(&format!("env_maker_chunk = load_func(sb_code, \"{sb_chunk}\");"), rng)));
        sb.push_str("                local stage2 = function()\n");
        sb.push_str(&format!("                    {}\n", cf_wrap::wrap_stmt("s.data = parts[2];", rng)));
        sb.push_str(&format!("                    {}\n", cf_wrap::wrap_stmt("s.len = #s.data;", rng)));
        sb.push_str(&format!("                    {}\n", cf_wrap::wrap_stmt("s.idx = 1; s.kidx = 0;", rng)));
        sb.push_str(&format!("                    {}\n", cf_wrap::wrap_stmt("s.buf = {}; s.res = {};", rng)));
        sb.push_str(&format!("                    {}\n", cf_wrap::wrap_stmt(&format!("s.pc = {pc_state0}; s.bc = 0; s.f = 0; s.p1 = 0; s.p2 = 0; s.w = 0; s.u = 0; s.ptr = 0;"), rng)));
        sb.push_str(&format!("                    {}\n", cf_wrap::wrap_stmt("s.r_flg = false; s.r_vals = {}; s.r_len = 0; s.tail_flg = false;", rng)));
        sb.push_str(&format!("                    return q:{m_run}(s);\n"));
        sb.push_str("                end\n");
        sb.push_str("                local env_maker = false;\n");
        sb.push_str(&format!("                {}\n", cf_wrap::wrap_stmt("env_maker = env_maker_chunk and env_maker_chunk(stage2) or stage2;", rng)));
        sb.push_str("                return env_maker();\n            end)({\n");
        sb.push_str(&format!("                data = data, pc = {pc_state0}, insts = {{}}, tamper = {tamper_val}, handlers = {{}},\n"));
        sb.push_str("                r_flg = false, r_vals = {}, r_len = 0, tail_flg = false,\n");
        sb.push_str("                idx = 1, len = #data, k = {}, kidx = 0, buf = {}, memo = {},\n");
        sb.push_str(&format!("                unpack = q.{k_un}, char = q.{k_ch}, byte = q.{k_by}, floor = q.{k_fl}, insert = q.{k_ins}, concat = q.{k_cat}, remove = q.{k_rem}, reverse = q.{k_rev},\n"));
        sb.push_str("                bc = 0, res = {}, f = 0, p1 = 0, p2 = 0, w = 0, u = 0, ptr = 0\n");
        sb.push_str("            });\n        end\n");
        // 第 3/5 类：内建别名 + 样板填充函数，作为壳表的附加字段（sample2 的壳里
        // 就挂着 `RP=bit32.band` / `u2=function(v)end` 这类字段）
        if !pad_fields.is_empty() {
            sb.push_str("    , ");
            sb.push_str(&pad_fields.join("\n    , "));
            sb.push('\n');
        }
        sb.push_str(&format!("    , {k_un} = unpack or table.unpack, {k_ch} = string.char, {k_by} = string.byte, {k_fl} = math.floor, {k_ins} = table.insert, {k_cat} = table.concat, {k_rem} = table.remove, {k_rev} = string.reverse, {k_lf} = loadstring or load, {k_gm} = string.gmatch\n    }});\n"));
        // 第 6 类：IIFE（sample2 有 8 处 `(function(`，多为「只取出函数值存槽位」）。
        // 放在壳表建好之后、`m_main` 调用之前；每条用 `do ... end;` 包住，
        // 避免压缩器去分号后两个 IIFE 粘成链式调用 `f()(g)`。
        // 另外这些句子会经过 cf_wrap 风格的重排，槽位号可能撞上解码器自己用的键，
        // 所以只保留「不写任何字段」的纯读形态。
        for _ in 0..rng.range(3, 7) {
            sb.push_str(&format!("    {}\n", crate::VM::shell_pad::iife_stmt(rng, &shell_obj)));
        }
        sb.push_str(&format!("    return {}:{}({});\nend\n", shell_obj, m_main, v_data));
        let script = sb;
        let post_pairs: Vec<(&str, &str)> = vec![
            ("data", f_data.as_str()),
            ("pc", f_pc.as_str()),
            ("idx", f_idx.as_str()),
            ("kidx", f_kidx.as_str()),
            ("buf", f_buf.as_str()),
            ("res", f_res.as_str()),
            ("bc", f_bc.as_str()),
            ("f", f_f.as_str()),
            ("p1", f_p1.as_str()),
            ("p2", f_p2.as_str()),
            ("w", f_w.as_str()),
            ("u", f_u.as_str()),
            ("ptr", f_ptr.as_str()),
            ("k", f_k.as_str()),
            ("memo", f_memo.as_str()),
            ("len", f_len.as_str()),
            ("insts", f_insts.as_str()),
            ("tamper", f_tamper.as_str()),
            ("handlers", f_handlers.as_str()),
            ("r_flg", f_r_flg.as_str()),
            ("r_vals", f_r_vals.as_str()),
            ("r_len", f_r_len.as_str()),
            ("tail_flg", f_tail_flg.as_str()),
            ("unpack", f_unpack.as_str()),
            ("char", f_char.as_str()),
            ("byte", f_byte.as_str()),
            ("floor", f_floor.as_str()),
            ("insert", f_insert.as_str()),
            ("concat", f_concat.as_str()),
            ("remove", f_remove.as_str()),
            ("reverse", f_reverse.as_str()),
        ];
        let script = Self::rename_lua_idents(&script, &post_pairs);
        // 2) 常量局部变量注入（消毒之后插入，字面量保留）
        let script = script.replacen(
            "\n    local _;\n",
            &format!("\n    local _;\n    local a, b, c, d = {}, {}, {}, {};\n", va, vb, vc, vd),
            1,
        );
        (script, f_entry)
    }

    fn itoa(mut n: usize) -> String {
        let mut s = vec![];
        loop {
            s.push((b'0' + (n % 10) as u8) as char);
            n /= 10;
            if n == 0 { break; }
        }
        s.reverse();
        s.into_iter().collect()
    }

    // 内部状态表字段名的整词替换：跳过字符串字面量（支持 \ 转义），先把壳里
    // 引用全局库函数的表达式打成占位符（保护 unpack or table.unpack / string.char
    // 等全局引用，避免被整词替换误伤），替换完成后再恢复占位符。
    fn rename_lua_idents(code: &str, pairs: &[(&str, &str)]) -> String {
        use std::collections::HashMap;

        // 壳中引用的全局库函数（按长度从长到短，避免短串先匹配占用长串前缀）
        const PROTECT: &[&str] = &[
            "unpack or table.unpack",
            "string.reverse",
            "string.gmatch",
            "loadstring or load",
            "table.unpack",
            "string.char",
            "string.byte",
            "math.floor",
            "table.insert",
            "table.concat",
            "table.remove",
        ];

        let bytes = code.as_bytes();
        let mut buf = bytes.to_vec();
        for (idx, pat) in PROTECT.iter().enumerate() {
            let pat_bytes = pat.as_bytes();
            let mut new_buf: Vec<u8> = Vec::with_capacity(buf.len() + 8);
            let mut i = 0usize;
            while i < buf.len() {
                if buf[i..].starts_with(pat_bytes) {
                    new_buf.push(0x01);
                    new_buf.extend_from_slice(Self::itoa(idx).as_bytes());
                    new_buf.push(0x01);
                    i += pat_bytes.len();
                } else {
                    new_buf.push(buf[i]);
                    i += 1;
                }
            }
            buf = new_buf;
        }

        let mut map: HashMap<&[u8], &str> = HashMap::with_capacity(pairs.len());
        for (from, to) in pairs {
            map.insert(from.as_bytes(), to);
        }

        let is_ident_start = |c: u8| c.is_ascii_alphabetic() || c == b'_';
        let is_ident_char = |c: u8| c.is_ascii_alphanumeric() || c == b'_';

        let mut out: Vec<u8> = Vec::with_capacity(buf.len() + pairs.len() * 8);
        let mut i = 0usize;
        while i < buf.len() {
            let c = buf[i];
            if c == b'"' || c == b'\'' {
                let quote = c;
                let start = i;
                i += 1;
                while i < buf.len() {
                    let d = buf[i];
                    if d == b'\\' {
                        i += 2;
                        continue;
                    }
                    i += 1;
                    if d == quote { break; }
                }
                out.extend_from_slice(&buf[start..i]);
                continue;
            }
            if is_ident_start(c) {
                let start = i;
                i += 1;
                while i < buf.len() && is_ident_char(buf[i]) {
                    i += 1;
                }
                let word = &buf[start..i];
                if let Some(rep) = map.get(word) {
                    out.extend_from_slice(rep.as_bytes());
                } else {
                    out.extend_from_slice(word);
                }
                continue;
            }
            out.push(c);
            i += 1;
        }
        let mut out_str = String::from_utf8(out).expect("非 UTF-8 输出");
        for (idx, pat) in PROTECT.iter().enumerate() {
            let placeholder = format!("\u{1}{}\u{1}", Self::itoa(idx));
            out_str = out_str.replace(&placeholder, pat);
        }
        out_str
    }
}