// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use std::time::SystemTime;
use rand::{rngs::StdRng, Rng, SeedableRng, random};

use crate::VM::cf_wrap;
use crate::VM::Control_Flow::Control_flow::ControlFlowBuilder;
use crate::VM::VM_Backend::Generator::GenRng;
use crate::VM::VM_Backend::Sandbox::generate_sandbox;

mod decoder;


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

/// 匹配窗口（与链回溯上限共同决定编码复杂度）。
const WINDOW: usize = 65535;
/// 单个位置最多沿链回溯多少个候选，防止高重复输入退化。
const MAX_CHAIN: usize = 512;
/// 最小匹配长度（短于此长度用 Raw 更便宜）。
const MIN_MTCH: usize = 3;
/// 单次匹配的最大长度（与旧版一致，token 里 span-3 只有 1 字节）。
const MAX_SPAN: usize = 258;

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

    /// 3 字节键 → 16 bit 哈希（乘法散列，避免 64K 桶取模）。
    #[inline]
    fn hash3(data: &[u8], pos: usize) -> usize {
        let v = (data[pos] as u32)
            | ((data[pos + 1] as u32) << 8)
            | ((data[pos + 2] as u32) << 16);
        ((v.wrapping_mul(0x9E37_79B1)) >> 16) as usize & 0xFFFF
    }

    fn encode_stream(input: &[u8]) -> Vec<u8> {
        let len = input.len();
        if len == 0 {
            return Vec::new();
        }

        let mut costs = vec![u32::MAX; len + 1];
        let mut links = vec![Step::Raw; len + 1];
        costs[0] = 0;
        // hash chain：head[h] 为该 3 字节哈希最近出现的位置，chain[p] 为同哈希的上一处。
        let mut head = vec![usize::MAX; 1 << 16];
        let mut chain = vec![usize::MAX; len + 3];

        for i in 0..len {
            if costs[i] == u32::MAX {
                continue;
            }

            let cost_raw = costs[i] + 9;
            if cost_raw < costs[i + 1] {
                costs[i + 1] = cost_raw;
                links[i + 1] = Step::Raw;
            }

            let max_span = std::cmp::min(MAX_SPAN, len - i);

            let mut optimal_strides = [0u16; MAX_SPAN + 1];
            let mut peak_span = 0;

            if max_span >= 3 && i >= 3 {
                let mut probe = head[Self::hash3(input, i)];
                let mut steps = 0usize;
                while probe != usize::MAX && steps < MAX_CHAIN && i - probe <= WINDOW {
                    steps += 1;
                    if input[probe + peak_span] == input[i + peak_span] {
                        let mut current_span = 0;
                        while current_span < max_span
                            && input[probe + current_span] == input[i + current_span]
                        {
                            current_span += 1;
                        }
                        if current_span > peak_span {
                            let mut l = peak_span + 1;
                            while l <= current_span {
                                optimal_strides[l] = (i - probe) as u16;
                                l += 1;
                            }
                            peak_span = current_span;
                            if peak_span >= max_span {
                                break;
                            }
                        }
                    }
                    probe = chain[probe];
                }
            }

            // 搜索完成后再把当前位置登记进链：若先登记，head 会返回 i 本身，
            // i - probe == 0 会退化成「自己匹配自己」，span 直接顶到上限。
            if i + 3 <= len {
                let h = Self::hash3(input, i);
                chain[i] = head[h];
                head[h] = i;
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
}
