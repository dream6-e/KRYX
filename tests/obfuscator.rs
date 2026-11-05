// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use kryx::obfuscator::generate;
use std::fs;
use std::process::Command;

const SEEDS: [u64; 3] = [1234567890123456, 9876543210123456, 5555555555555555];
fn source_cases() -> Vec<String> {
    vec![
        "".into(),
        "return".into(),
        "return nil".into(),
        "return nil, false, true, nil".into(),
        "local x=2; local y=3; print(x,y,nil); print(); return x+y, x-y, x*y, x/y, x//y, x%y, x^y"
            .into(),
        "local x=5; local x,y=x+1,x; return x,y".into(),
        "local a,b,c=1; local x,y=10,20,30; return a,b,c,x,y".into(),
        "return 'abc'..'def', #'', #'hello', not 0, not nil".into(),
        "return 1<2, 1<=1, 2>1, 2>=2, 1==2, 1~=2, 'a'<'b', false==nil".into(),
        "return -0, -1, 0/0, 1/0, -(0), 0x1f, 0b101, 9_007_199_254_740_992".into(),
        "const x = 1; print('a]]b',x); return x".into(),
        "local a=1; local a,a=a+1,a+2; return a".into(),
        "print(nil,nil); return nil,nil".into(),
        include_str!("../examples/vm_stage1.lua").into(),
    ]
}

#[test]
fn generator_is_seeded_reproducible_and_refuses_unimplemented_constructs() {
    let source = b"local a=7; print(a,nil); return a+1";
    let one = generate(source, SEEDS[0]).unwrap();
    assert_eq!(one, generate(source, SEEDS[0]).unwrap());
    assert_ne!(one, generate(source, SEEDS[1]).unwrap());
    assert!(one.contains("):R0()(...)") && one.contains("q[6]") && one.contains("pcall"));
    assert!(kryx::parser::parse(one.as_bytes()).is_ok());
    assert!(generate(source, 42).is_err());
    assert_eq!(
        generate(
            include_bytes!("../examples/vm_stage1.lua"),
            5122438661592891
        )
        .unwrap(),
        include_str!("../examples/vm_stage1.K.lua")
    );
    let random = kryx::obfuscator::seed::generate().unwrap();
    assert!((1_000_000_000_000_000..=9_999_999_999_999_999).contains(&random));
    for s in [
        "return 1.5",
        "return 'a\\nb'",
        "print(string.len('x'))",
        "if true then return 1 end",
        "local x: number=1; return x",
        "return true and false",
        "local print=1; print()",
        "return game",
    ] {
        assert!(generate(s.as_bytes(), SEEDS[0]).is_err(), "{s}");
    }
}

fn quoted(bytes: &[u8]) -> String {
    let mut result = String::from("\"");
    for b in bytes {
        result.push_str(&format!("\\{:03}", b));
    }
    result.push('"');
    result
}

#[test]
fn original_and_generated_programs_execute_identically_when_luau_is_available() {
    let Some(vm) = std::env::var_os("LUAU_VM") else {
        eprintln!("LUAU_VM not set; execution equivalence test skipped");
        return;
    };
    let dir = std::env::temp_dir().join(format!(
        "kryx-vm-test-{}-{}",
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
    let runner = dir.join("runner.luau");
    let helper = r#"
local function run(source)
    local logs={}
    local fn=assert(loadstring(source))
    local env=setmetatable({print=function(...) table.insert(logs,table.pack(...)) end},{__index=getfenv()})
    setfenv(fn,env)
    local result=table.pack(pcall(fn))
    assert(result[1],tostring(result[2]))
    return result,logs
end
local function compare(a,b,label)
    assert(a.n==b.n,label..' count '..a.n..' vs '..b.n)
    for i=1,a.n do
        local x,y=a[i],b[i]
        assert(type(x)==type(y),label..' type '..i)
        if type(x)=='number' and x~=x then assert(y~=y,label..' NaN')
        else assert(x==y,label..' value '..i) end
        if type(x)=='number' and x==0 then assert(1/x==1/y,label..' signed zero') end
    end
end
local function test(a,b,label)
    local x,l=run(a);local y,m=run(b);compare(x,y,label..' returns')
    assert(#l==#m,label..' print count')
    for i=1,#l do compare(l[i],m[i],label..' print '..i) end
end
"#;
    let mut script = helper.to_owned();
    let mut cases = source_cases();
    cases.push(format!(
        "local x = '{}'; print(x); return #x, x",
        "ab".repeat(200)
    ));
    cases.push(format!(
        "return {}",
        std::iter::repeat("1")
            .take(150)
            .collect::<Vec<_>>()
            .join("+")
    ));
    cases.push("return '你好🙂', # '你好🙂'".to_owned());
    // Fixed-seed generated arithmetic inputs exercise many expression tree shapes.
    let mut state = 42u32;
    for _ in 0..150 {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        let a = state % 1000;
        let b = (state >> 10) % 99 + 1;
        let c = (state >> 17) % 77 + 1;
        cases.push(format!(
            "local x={a}; local y={b}; return (x+y)*{c}, x//y, x%y, x<y, not (x==y)"
        ));
    }
    for (i, source) in cases.iter().enumerate() {
        for seed in SEEDS {
            let output = generate(source.as_bytes(), seed).unwrap();
            assert!(kryx::parser::parse(output.as_bytes()).is_ok());
            script.push_str(&format!(
                "test({},{},'case {i} seed {seed}')\n",
                quoted(source.as_bytes()),
                quoted(output.as_bytes())
            ));
        }
    }
    script.push_str(&format!(
        "test({},{},'committed example output')\n",
        quoted(include_bytes!("../examples/vm_stage1.lua")),
        quoted(include_bytes!("../examples/vm_stage1.K.lua"))
    ));
    let source = b"print('trigger')";
    let generated = generate(source, SEEDS[0]).unwrap();
    script.push_str(&format!(
        r#"
local marker={{}}
local function failure(src)
    local fn=assert(loadstring(src))
    setfenv(fn,setmetatable({{print=function() error(marker) end}},{{__index=getfenv()}}))
    local ok,err=pcall(fn);assert(not ok and err==marker,'error object identity')
end
failure({});failure({});
"#,
        quoted(source),
        quoted(generated.as_bytes())
    ));
    script.push_str("print('VM equivalence cases passed')\n");
    fs::write(&runner, script).unwrap();
    let result = Command::new(vm)
        .arg(&runner)
        .output()
        .expect("failed to start LUAU_VM");
    eprintln!(
        "{} source cases x {} seeds, plus the checked-in output and error object case",
        cases.len(),
        SEEDS.len()
    );
    assert!(
        result.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}
