// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use rand::{thread_rng, Rng};
use super::kx1;

pub struct AntiTamperResult {
    pub setup: String,
    pub guards: Vec<String>,
    pub trigger: String,
    pub expected_final: i64,
}

fn rand_var() -> String {
    let mut rng = thread_rng();
    let len = rng.gen_range(7..=12);
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect();
    let name: String = (0..len).map(|_| chars[rng.gen_range(0..chars.len())]).collect();
    crate::VM::Names::register(&name);
    name
}

fn random_string() -> String {
    let mut rng = thread_rng();
    let len = rng.gen_range(8..=16);
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect();
    (0..len).map(|_| chars[rng.gen_range(0..chars.len())]).collect()
}

fn poly_hash(s: &str) -> u32 {
    let mut h: u64 = 5381;
    for b in s.bytes() {
        h = (h * 33 + b as u64) % 4294967296;
    }
    h as u32
}

fn shuffle_vec(vec: &mut Vec<usize>) {
    let mut rng = thread_rng();
    for i in (1..vec.len()).rev() {
        let j = rng.gen_range(0..=i);
        vec.swap(i, j);
    }
}

/// 旧入口（保留兼容）：不带 KX1 池。
pub fn generate_split(use_debug: bool, key_var: &str) -> AntiTamperResult {
    split_impl(use_debug, key_var, None)
}

/// 带 KX1 加密池的入口。
///
/// `shell` 是外层壳表变量名；`keys` 是壳表里 10 个 bit32/内建字段名
/// `[floor, char, concat, pcall, bxor, band, bor, lshift, rshift, bnot]`；
/// `kx` 是 KX1 额外要的 5 个 `[countlz, countrz, byteswap, lrotate, rrotate]`。
pub fn generate_split_kx1(
    use_debug: bool,
    key_var: &str,
    shell: &str,
    keys: &[&str; 10],
    kx: &[&str; 5],
) -> AntiTamperResult {
    split_impl(use_debug, key_var, Some((shell, keys, kx)))
}

fn split_impl(
    use_debug: bool,
    key_var: &str,
    kxenv: Option<(&str, &[&str; 10], &[&str; 5])>,
) -> AntiTamperResult {
    let mut rng = thread_rng();
    
    let v_env = rand_var();
    let v_net = rand_var();
    let v_crash = rand_var();
    let v_dec = rand_var();
    let v_res = rand_var();
    let v_pool = rand_var();

    // 将所有敏感 API 存入 KX1 加密池。
    // 旧版是「(b + key) % 256」的单字节加法 —— 暴力 256 次就能还原。
    // 现在改为 KX1 流密码（见 cipher/kx1.lua 与 VM_Backend/kx1.rs）。
    let strings = vec![
        "debug", "pcall", "sethook", "gethook", "getinfo", "C", "string", "dump", "error", "info", "math"
    ];
    let add_key: u8 = rng.gen_range(10..240);
    let kx_key = kx1::random_key(&mut rng);
    let kx_nonce: u32 = rng.random();
    let mut pool_entries = Vec::new();
    for s in &strings {
        let hash = poly_hash(s);
        let enc = if kxenv.is_some() {
            kx1::encrypt(s.as_bytes(), &kx_key, kx_nonce)
        } else {
            s.bytes().map(|b| b.wrapping_add(add_key)).collect()
        };
        let lit: Vec<String> = enc.iter().map(|b| b.to_string()).collect();
        pool_entries.push(format!("[{}]={{{}}}", hash, lit.join(",")));
    }

    // 生成一个随机变量名用于毒药表（Poison Pill）注入
    let rand_str = random_string();
    let rand_hash = poly_hash(&rand_str);
    let enc = if kxenv.is_some() {
        kx1::encrypt(rand_str.as_bytes(), &kx_key, kx_nonce)
    } else {
        rand_str.bytes().map(|b| b.wrapping_add(add_key)).collect()
    };
    let lit: Vec<String> = enc.iter().map(|b| b.to_string()).collect();
    pool_entries.push(format!("[{}]={{{}}}", rand_hash, lit.join(",")));

    let pool_data = pool_entries.join(",");

    let mut setup = String::new();
    // 使用 getgenv() 完美适配 Roblox 执行器全局环境
    setup.push_str(&format!("local {} = getgenv and getgenv() or getfenv and getfenv() or _ENV or _G or {{}};\n", v_env));
    
    // 纯物理爆栈导致卡死，无视 Roblox 的 string.rep / 内存上限等沙盒过滤
    setup.push_str(&format!(
    "local function {}() \
        local j,s,k,v=_ENV,false;local t={{}};local p=type;if not k then v=s end;if p(t)~=\"table\" then p=j end;repeat p={{}} until v; \
         local function f() pcall(f) pcall(f) end; \
         pcall(f); \
     local function we(x) return not x end;local gd if we(gd) then while we(s) do end;end \
     end;\n",
    v_crash
));
    setup.push_str(&format!("local {} = {{{}}};\n", v_pool, pool_data));
    // 解密器。
    //
    // 关键约束：`at.setup` 插在**壳表构造之前**。壳表是外层
    // `({...}):J()(...)` 的实参，此刻仍是 nil，所以这里绝不能引用
    // 壳表字段，只能用 bit32 / math / string 的全局直取。
    let v_kxdec = rand_var();
    let v_kxmul = rand_var();
    let _ = kxenv;
    if kxenv.is_some() {
        let kw = kx1::keywords(&kx_key);
        let key_lit = kw.iter().map(|v| format!("0x{:X}", v)).collect::<Vec<_>>().join(",");
        setup.push_str(&format!(
            "local {m} = function(a,b) a=a%4294967296;b=b%4294967296;\
             local a0=a%65536;local a1=(a-a0)/65536;\
             local b0=b%65536;local b1=(b-b0)/65536;\
             return (a0*b0+((a0*b1+a1*b0)%65536)*65536)%4294967296 end; local _ = {m};\n",
            m = v_kxmul
        ));
        setup.push_str(&kx1::lua_decrypt_lib(
            &v_pool, &key_lit, &kx_nonce.to_string(),
            &v_kxmul,
            "bit32.lshift", "bit32.rshift", "bit32.rrotate", "bit32.lrotate",
            "bit32.countlz", "bit32.countrz", "bit32.byteswap",
            "bit32.band", "bit32.bxor", "bit32.bor", "bit32.bnot",
            "math.floor", "string.sub", "string.char", "table.concat",
            &v_kxdec,
        ));
    } else {
        setup.push_str(&format!(
            "local function {}(e) local s='';for i=1,#e do s=s..string.char((e[i]+256-{})%256) end;\
             return s end;\n", v_kxdec, add_key
        ));
    }

    // 解密入口。写成 `local f = function(...)` 而不是 `local function f`，
    // 副作用上等价，但末尾的裸引用会命中 Reshape 的 bare_ref_global，
    // 从而不被提升成 `X:d(u,h)` —— 方法化会多插一个 u 实参，运行时立刻 nil。
    setup.push_str(&format!(
        "local function {}(h) local e = {}[h]; if not e then return nil end; \
         return {}(e) end; local _ = {};\n",
         v_dec, v_pool, v_kxdec, v_dec
    ));
    // 末尾那句裸引用（不是调用位置）会让 Reshape::bare_ref_global 命中，
    // 从而跳过「把 depth-0 局部函数提升成 v:key(u,...)」——方法化会凭空
    // 多插一个 u 实参，把 h 顶到第二位，运行时立刻 nil。
    setup.push_str(&format!(
        "local function {}(h) \
            local xc,yu=true;local s = {}(h); if not s then return yu end; \
             return xc and {}[s]; \
         end; local _ = {};\n",
         v_res, v_dec, v_env, v_dec
    ));
    setup.push_str(&format!("local {}={{}};\n", v_net));

    let mut current_expected: i64 = rng.gen_range(1000..9999);
    let initial_token = current_expected;
    
    let mut guards_indices = vec![0, 1, 2, 3, 4, 5, 7];
    shuffle_vec(&mut guards_indices);
    guards_indices.push(6);
    shuffle_vec(&mut guards_indices);
    
    let mut guards_code = Vec::new();
    
    for i in 0..guards_indices.len() {
        let delta = rng.gen_range(10..99);
        let guard_type = guards_indices[i];
        
        let next_good = if i == guards_indices.len() - 1 {
            format!("return k+{}", delta)
        } else {
            format!("return {}[{}](k+{})", v_net, i + 1, delta)
        };
        
        let next_bad = if i == guards_indices.len() - 1 {
            format!("return k-{}", rng.gen_range(100..999))
        } else {
            format!("return {}[{}](k-{})", v_net, i + 1, rng.gen_range(100..999))
        };
        
        let mut check_code = String::new();
        match guard_type {
            0 => {
                let fnv_pcall = poly_hash("pcall");
                let fnv_string = poly_hash("string");
                let fnv_math = poly_hash("math");
                // 用哈希组精确取值校验，避免受 pairs 迭代 __index 失效的影响
                check_code = format!(
                    "local sc_val = 0; \
                     local chk = {{{}, {}, {}}}; \
                     for idx = 1, 3 do \
                         if type({}(chk[idx])) ~= 'nil' then sc_val = sc_val + 1 end \
                     end; \
                     if sc_val ~= 3 then {} else {} end\n",
                    fnv_pcall, fnv_string, fnv_math, v_res, next_bad, next_good
                );
            }
            1 => {
                let hash_pcall = poly_hash("pcall");
                check_code = format!(
                    "local z = setmetatable({{}}, {{ \
                        [\"__\"..\"add\"]=function(a_)return a_ end, \
                        [\"__\"..\"sub\"]=function(a_)return a_ end, \
                        [\"__\"..\"mul\"]=function(a_)return a_ end, \
                        [\"__\"..\"call\"]=function(...)return ... end \
                     }}); \
                     local p={}({}); if not p then {} else \
                     local st,r=p(function() local x=z+z-z*z; local y=z(z); return x==z and y==z end); \
                     if not st or not r then {} else {} end end\n",
                    v_res, hash_pcall, next_bad, next_bad, next_good
                );
            }
            2 => {
                if use_debug {
                    let hash_debug = poly_hash("debug");
                    let hash_pcall = poly_hash("pcall");
                    let hash_sethook = poly_hash("sethook");
                    let hash_gethook = poly_hash("gethook");
                    let hash_info = poly_hash("info");
                    // Luau Roblox 自适应：如果没有 sethook，探测 info（Luau特征），符合则放行
                    check_code = format!(
                        "local d_={}({}); local p={}({}); \
                         if not (d_ and p) then {} else \
                         local sh = d_[{}({})]; local gh = d_[{}({})]; \
                         if not (sh and gh) then \
                             if d_[{}({})] then {} else {} end \
                         else \
                             local ok, h = p(gh); \
                             if not ok then {} else \
                             local c_ = 0; local ok2 = p(sh, function() c_=c_+1 end, string_char(99)); \
                             if not ok2 then {} else \
                             local function tmp() end; tmp(); p(sh); \
                             if c_ < 1 then {} else {} end end end end end\n",
                        v_res, hash_debug, v_res, hash_pcall,
                        next_bad,
                        v_dec, hash_sethook, v_dec, hash_gethook,
                        v_dec, hash_info, next_good, next_bad,
                        next_bad,
                        next_bad,
                        next_bad, next_good
                    );
                } else {
                    check_code = format!("{}\n", next_good);
                }
            }
            3 => {
                if use_debug {
                    let hash_debug = poly_hash("debug");
                    let hash_pcall = poly_hash("pcall");
                    let hash_getinfo = poly_hash("getinfo");
                    let hash_info = poly_hash("info");
                    let hash_C = poly_hash("C");
                    check_code = format!(
                        "local d_={}({}); local p={}({}); \
                         if not (d_ and p) then {} else \
                         local gi = d_[{}({})]; \
                         if not gi then \
                             if d_[{}({})] then {} else {} end \
                         else \
                             local ok, inf = p(gi, p); \
                             if not ok or type(inf)~='table' then {} else \
                             local w=inf.what; local h=5381; \
                             for idx=1,#w do h=(h*33+string_byte(w,idx))%4294967296 end; \
                             if h~={} then {} else {} end end end end\n",
                        v_res, hash_debug, v_res, hash_pcall,
                        next_bad,
                        v_dec, hash_getinfo,
                        v_dec, hash_info, next_good, next_bad,
                        next_bad,
                        hash_C, next_bad, next_good
                    );
                } else {
                    check_code = format!("{}\n", next_good);
                }
            }
            4 => {
                let hash_pcall = poly_hash("pcall");
                let hash_error = poly_hash("error");
                check_code = format!(
                    "local p={}({}); local e={}({}); \
                     if not p or not e then {} else \
                     local st, r = p(function() e(1) end); \
                     if st then {} else {} end end\n",
                    v_res, hash_pcall, v_res, hash_error,
                    next_bad, next_bad, next_good
                );
            }
            5 => {
                let hash_string = poly_hash("string");
                let hash_pcall = poly_hash("pcall");
                let hash_dump = poly_hash("dump");
                let hash_debug = poly_hash("debug");
                let hash_info = poly_hash("info");
                check_code = format!(
                    "local s={}({}); local p={}({}); local d_={}({}); \
                     if not (s and p) then {} else \
                     local du=s[{}({})]; \
                     if not du then \
                         if d_ and d_[{}({})] then {} else {} end \
                     else \
                         local st = p(du, function() end); \
                         if not st then \
                             if d_ and d_[{}({})] then {} else {} end \
                         else \
                             {} \
                         end \
                     end end\n",
                     v_res, hash_string, v_res, hash_pcall, v_res, hash_debug,
                     next_bad,
                     v_dec, hash_dump,
                     v_dec, hash_info, next_good, next_bad,
                     v_dec, hash_info, next_good, next_bad,
                     next_good
                );
            }
            6 => {
                check_code = format!(
                    "local t=false; local v1=1; local o={}; \
                     t = o and o==v1; \
                     if t then {} else {} end\n",
                    rng.gen_range(100..999), next_bad, next_good
                );
            }
            7 => {
                check_code = format!(
                    "local e={}; \
                     if type(e)~='table' then {} else \
                     local p=setmetatable({{}}, {{ \
                        [\"__\"..\"tostring\"]={}, \
                        [\"__\"..\"index\"]={}, \
                        [\"__\"..\"newindex\"]={}, \
                        [\"__\"..\"call\"]={} \
                     }}); \
                     pcall(function() e[{}({})]=p end); \
                     {} end\n",
                    v_env, next_bad, v_crash, v_crash, v_crash, v_crash, v_dec, rand_hash, next_good
                );
            }
            _ => {
                check_code = format!("{}\n", next_good);
            }
        }
        
        current_expected += delta;
        let single_guard_raw = format!("{}[{}]=function(k)\n{}end;\n", v_net, i, check_code);
        let minified_guard = minify_lua(&single_guard_raw);
        guards_code.push(minified_guard);
    }
    
    let v_jump = rand_var();
    let mut trigger = String::new();
    trigger.push_str(&format!("{}={}[0]({});\n", key_var, v_net, initial_token));
    trigger.push_str(&format!(
        "local {} = setmetatable({{}}, {{ [\"__\"..\"index\"] = function() return {} end }});\n",
        v_jump, v_crash
    ));
    trigger.push_str(&format!("{}[{}] = function() end;\n", v_jump, current_expected));
    trigger.push_str(&format!("{}[{}]();\n", v_jump, key_var));
    
    AntiTamperResult {
        setup: minify_lua(&setup),
        guards: guards_code,
        trigger: minify_lua(&trigger),
        expected_final: current_expected,
    }
}

fn minify_lua(code: &str) -> String {
    code.lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .collect::<Vec<&str>>()
        .join(" ")
        .replace("= ", "=")
        .replace(" =", "=")
        .replace(" + ", "+")
        .replace(" - ", "-")
        .replace(" == ", "==")
        .replace(" ~= ", "~=")
}