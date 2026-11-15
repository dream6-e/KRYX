// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
pub mod token;
pub mod lexer;
pub mod ast;
pub mod parser;
pub mod scope;
pub mod codegen;
pub mod renamer;
pub mod packer;

use std::collections::HashMap;
use rand::{rng, Rng, seq::SliceRandom};
use crate::compiler::error::{LuaError, LuaResult, SyntaxError, set_active_source};
use ast::VarId;
use token::TokenType;


/// 名字池：52 个洗牌单字母在前（优先单字母），之后按 base-52 依次生成多字母组合；
/// 跳过 Lua 关键字与安全全局名。按 next_except 需要懒生成并缓存，保证全局
/// 名字编码空间与 codegen 的 map_string 互不重叠（start_idx 用 pool_counter）。
struct NamePool<'a> {
    letters: &'a [char],
    ren: &'a renamer::Renamer,
    counter: usize,
    generated: Vec<String>,
}

impl<'a> NamePool<'a> {
    fn new(letters: &'a [char], ren: &'a renamer::Renamer) -> Self {
        Self { letters, ren, counter: 0, generated: Vec::new() }
    }

    fn generate_next(&mut self) -> String {
        let base = self.letters.len();
        loop {
            let mut n = self.counter;
            self.counter += 1;
            let mut candidate = String::new();
            loop {
                candidate.push(self.letters[n % base]);
                n /= base;
                if n == 0 { break; }
            }
            let candidate: String = candidate.chars().rev().collect();
            if self.ren.is_keyword(&candidate) || self.ren.is_safe_global(&candidate) { continue; }
            return candidate;
        }
    }

    fn next_except(&mut self, banned: &std::collections::HashSet<&str>) -> String {
        let mut idx = 0;
        loop {
            if idx == self.generated.len() {
                let name = self.generate_next();
                self.generated.push(name);
            }
            if !banned.contains(self.generated[idx].as_str()) {
                return self.generated[idx].clone();
            }
            idx += 1;
        }
    }
}

pub struct Compressor;

impl Compressor {
    pub fn compress(input: &str) -> LuaResult<String> {
        set_active_source(input.to_string());
        
        let processed_input = input.to_string();

        let mut lex = lexer::Lexer::new(&processed_input);
        let mut tokens = lex.tokenize();
        for tok in &mut tokens {
            if matches!(
                tok.text.as_str(),
                "and" | "break" | "do" | "else" | "elseif" | "end" | "false" | "for" | "function"
                    | "if" | "in" | "local" | "nil" | "not" | "or" | "repeat" | "return"
                    | "then" | "true" | "until" | "while"
            ) {
                tok.token_type = TokenType::Keyword;
            }
        }
        
        let mut pars = parser::Parser::new(tokens);
        let mut root_block = pars.parse_block()?;
        
        let mut resolver = scope::ScopeResolver::new();
        root_block.resolve(&mut resolver);
        
        let ren = renamer::Renamer::new();
        let mut mapping = HashMap::new();
        
        let mut rng = rng();
        let mut wave1 = Vec::with_capacity(26);
        let mut wave2 = Vec::with_capacity(26);
        let mut alphabets: Vec<(char, char)> = (b'a'..=b'z')
            .zip(b'A'..=b'Z')
            .map(|(lower, upper)| (lower as char, upper as char))
            .collect();
            
        alphabets.shuffle(&mut rng);
        for (lower, upper) in alphabets {
            if rng.random_bool(0.5) { wave1.push(lower); wave2.push(upper); } 
            else { wave1.push(upper); wave2.push(lower); }
        }
        
        let mut single_letters = wave1;
        single_letters.extend(wave2);
        let base = single_letters.len();

        // 活跃区间染色重命名：
        // 1) 优先单字母（52 个洗牌字母优先分配），不够时再用多字母组合；
        // 2) 活跃区间 [定义位置, 最后使用位置] 不重叠的变量复用同一个名字
        //    —— 不同作用域/生存期不相交的变量共用名字（安全：词法作用域按声明点绑定）。
        let mut live_vars: Vec<(VarId, usize, usize, usize)> = Vec::new();
        for (&id, &usage) in &resolver.var_usage {
            if usage == 0 { continue; }
            if let Some(&(def, last)) = resolver.intervals.get(&id) {
                live_vars.push((id, usage, def, last));
            }
        }
        // 使用次数多的变量优先拿名字（单字母优先）
        live_vars.sort_by(|a, b| b.1.cmp(&a.1).then(a.2.cmp(&b.2)));

        let mut name_pool = NamePool::new(&single_letters, &ren);
        let mut assigned: Vec<(usize, usize, String)> = Vec::new();
        for (id, _usage, def, last) in live_vars {
            // 与已分配变量活跃区间重叠的名字不能用
            let mut banned: std::collections::HashSet<&str> = std::collections::HashSet::new();
            for (d2, l2, n2) in &assigned {
                if !(*l2 < def || *d2 > last) {
                    banned.insert(n2.as_str());
                }
            }
            let name = name_pool.next_except(&banned);
            mapping.insert(id, name.clone());
            assigned.push((def, last, name));
        }
        for (&id, &usage) in &resolver.var_usage {
            if usage == 0 {
                mapping.insert(id, "_".to_string());
            }
        }

        // 随机参数覆盖：function(a,a,b) —— 把函数体内 0 次使用的参数改成别的参数的名字，
        // 产生随机重复；luau/lua 均允许参数重名（最后一个生效）。
        // 安全条件：被改写的参数 u 在函数体内 0 次使用，且目标参数 t 满足：
        //   - t 在 u 之后（靠后）：t 的引用仍绑定到它自己（最后一个同名绑定），语义不变；
        //   - t 在 u 之前（靠前）：t 的引用会重绑定到被改写的 u（同名靠后者优先），
        //     因此仅当 t 也未被使用时才允许。
        for params in &resolver.param_lists {
            if params.len() < 2 { continue; }
            if !rng.random_bool(0.6) { continue; }
            let usage = |i: usize| resolver.var_usage.get(&params[i]).copied().unwrap_or(0);
            let mut unused: Vec<usize> = Vec::new();
            for i in 0..params.len() {
                if usage(i) == 0 { unused.push(i); }
            }
            if unused.is_empty() { continue; }
            let unused_i = unused[rng.random_range(0..unused.len())];
            // 目标优先：靠后的参数（优先已使用的）；靠后不存在时只允许靠前且未使用的参数
            let mut targets: Vec<usize> = Vec::new();
            if unused_i + 1 < params.len() {
                let used_later: Vec<usize> = (unused_i + 1..params.len()).filter(|&j| usage(j) > 0).collect();
                targets = if !used_later.is_empty() {
                    used_later
                } else {
                    (unused_i + 1..params.len()).collect()
                };
            } else {
                targets = (0..unused_i).filter(|&j| usage(j) == 0).collect();
            }
            if targets.is_empty() { continue; }
            let target = targets[rng.random_range(0..targets.len())];
            let target_name = mapping.get(&params[target]).cloned().unwrap_or_else(|| "_".to_string());
            if target_name == "_" { continue; }
            mapping.insert(params[unused_i], target_name);
        }

        let pool_counter = name_pool.counter;
        let ctx = codegen::CodegenContext {
            mapping,
            shuffled_chars: single_letters,
            map_string_start_idx: pool_counter,
        };
        
        let mut gen_tokens = Vec::new();
        root_block.to_tokens(&ctx, &mut gen_tokens);
        
        Ok(packer::Packer::pack(gen_tokens))
    }
}