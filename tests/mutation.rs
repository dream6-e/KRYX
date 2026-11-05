// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use std::fs;
use std::process::Command;

/// Deterministic token mutations compare acceptance with an optional official compiler.
#[test]
fn mutated_programs_match_official_parser_when_requested() {
    let Some(compiler) = std::env::var_os("LUAU_COMPILE") else {
        eprintln!("LUAU_COMPILE not set; mutation comparison skipped");
        return;
    };
    let seeds: &[&[u8]] = &[
        b"local a=1; local function f(x:number):number return x+a end; return f(2)",
        b"local t={x=3,[2]=5}; for i,v in pairs(t) do t[i]=v+1 end; return t",
        b"type A<T>={x:T}|nil; local a:A<number>=nil; if a then print(a.x) end",
        b"while true do if game then break else continue end end",
        b"local name=`Hello {game.Name}`; return name",
        b"export local x=3; export function f() return x end",
        b"const x=1; do local a=2; print(x,a) end",
        b"type F<T...>=(number,T...)->(T...)",
    ];
    let replacements: &[&[u8]] = &[
        b"end",
        b"if",
        b"then",
        b"else",
        b"local",
        b"const",
        b"function",
        b"return",
        b"do",
        b"while",
        b";",
        b",",
        b"=",
        b".",
        b":",
        b"+",
        b"-",
        b"(",
        b")",
        b"{",
        b"}",
        b"[",
        b"]",
        b"...",
        b"x",
        b"1",
        b"nil",
        b"\"a\"",
        b"::",
        b"?",
        b"@native",
        b"type",
        b"--x\n",
        b"<<",
        b">>",
        b"<",
        b">",
        b" ",
        b"\n",
    ];
    let dir = std::env::temp_dir().join(format!(
        "kryx-mutation-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&dir).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(dir.clone());
    let file = dir.join("case.luau");
    let mut state = 0x1234_5678_u32;
    let mut random = |n: usize| {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        state as usize % n
    };
    let mut mismatches = Vec::new();
    for _ in 0..1000 {
        let seed = seeds[random(seeds.len())];
        let tokens = kryx::lexer::lex(seed).unwrap();
        let mut pieces: Vec<Vec<u8>> = tokens
            .iter()
            .filter(|t| t.kind != kryx::lexer::TokenKind::Eof)
            .map(|t| seed[t.span.clone()].to_vec())
            .collect();
        let index = random(pieces.len());
        let replacement = replacements[random(replacements.len())].to_vec();
        match random(3) {
            0 => {
                pieces.remove(index);
            }
            1 => pieces[index] = replacement,
            _ => pieces.insert(index, replacement),
        }
        let source = pieces.concat();
        fs::write(&file, &source).unwrap();
        let official = Command::new(&compiler)
            .args(["--null", "--only-parse"])
            .arg(&file)
            .output()
            .expect("failed to start LUAU_COMPILE");
        let ours = kryx::parser::parse(&source);
        if official.status.success() != ours.is_ok() && mismatches.len() < 10 {
            mismatches.push(format!(
                "source={:?}\nofficial={} {:?}\nours={}",
                String::from_utf8_lossy(&source),
                official.status.success(),
                String::from_utf8_lossy(&official.stderr).lines().next(),
                ours.err()
                    .map_or_else(|| "accepted".to_owned(), |e| e.to_string())
            ));
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n\n"));
}
