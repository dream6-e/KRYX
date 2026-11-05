// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use kryx::ast::{Kind, Node};
use kryx::lexer::TokenKind;
use kryx::parser::parse;

fn find<'a>(node: &'a Node, predicate: &impl Fn(&Kind) -> bool) -> Option<&'a Node> {
    if predicate(&node.kind) {
        return Some(node);
    }
    node.children
        .iter()
        .find_map(|child| find(child, predicate))
}

#[test]
fn lossless_token_spans_and_original_bytes() {
    let source = b"--!strict\r\nlocal x = [=[text\n\xff]=] -- tail\r\nreturn x\n";
    let tree = parse(source).unwrap();
    assert_eq!(tree.source, source);
    let mut pos = 0;
    let mut comments = 0;
    for t in &tree.tokens {
        assert_eq!(t.span.start, pos);
        pos = t.span.end;
        if t.kind == TokenKind::Comment {
            comments += 1;
        }
    }
    assert_eq!(pos, source.len());
    assert_eq!(comments, 2);
    assert_eq!(tree.root.children.len(), 2);
}

#[test]
fn ast_expresses_precedence_and_assignment_lists() {
    let t = parse(b"a, b = -2^3^4, 1 + 2 * 3").unwrap();
    let assignment = &t.root.children[0];
    assert_eq!(assignment.kind, Kind::Assignment);
    assert_eq!(assignment.children[0].kind, Kind::TargetList);
    assert_eq!(assignment.children[0].children.len(), 2);
    let values = &assignment.children[1];
    assert_eq!(values.kind, Kind::ValueList);
    assert_eq!(values.children.len(), 2);
    let unary = &values.children[0];
    assert_eq!(unary.kind, Kind::Unary("-".into()));
    let power = &unary.children[0];
    assert_eq!(power.kind, Kind::Binary("^".into()));
    assert_eq!(power.children[1].kind, Kind::Binary("^".into()));
    let sum = &values.children[1];
    assert_eq!(sum.kind, Kind::Binary("+".into()));
    assert_eq!(sum.children[1].kind, Kind::Binary("*".into()));
}

#[test]
fn parses_representative_luau_and_roblox_constructs() {
    let cases: &[&[u8]] = &[
        b"local x: number = 0x1e+3; x += 1; x //= 2",
        b"export type Pair<T> = {first: T, second: T}; local function f<T>(x: T): T return x end",
        b"type T = {read foo: number, write foo: number, [string]: boolean}",
        b"local function f<T...>(...: T...): T... return ... end; return f(1,2)",
        b"for _, child in workspace:GetChildren() do if child:IsA('Part') then child.Transparency += 1 else continue end end",
        b"local t = { [1] = 'one', x = { 2, 3 }, function() return nil end }",
        b"local x = if local v = game then v.Name elseif false then 'a' else 'b'",
        b"local x = `hello {game:GetService('Players').LocalPlayer.Name}: {1 + 2}`",
        b"local x = `nested {`inside {1}`} end`",
        b"@native local function f(x: number): number return x end",
        b"export local answer = 42; export function get() return answer end",
        b"local function f<T>(x: T): T return x end; local x = f<<number>>(1)",
        b"repeat if false then break end until true; while true do continue end",
    ];
    for source in cases {
        let result = parse(source);
        assert!(
            result.is_ok(),
            "{}: {result:?}",
            String::from_utf8_lossy(source)
        );
    }
}

#[test]
fn parses_type_operator_precedence() {
    let t = parse(b"type T = A | (B & (C?))").unwrap();
    let union = find(&t.root, &|k| *k == Kind::TypeBinary("|".into())).unwrap();
    let intersection = find(&union.children[1], &|k| *k == Kind::TypeBinary("&".into())).unwrap();
    assert!(find(&intersection.children[1], &|k| *k == Kind::TypeOptional).is_some());
}

#[test]
fn rejects_bad_input_with_positions() {
    let cases: &[&[u8]] = &[
        b"local x =",
        b"local x = 1e+",
        b"local x = 0b102",
        b"local x = 'unterminated",
        b"local x = '\\xzz'",
        b"local x = '\\u{}'",
        b"local x = '\\256'",
        b"local x = `{{x}}`",
        b"local x = `{}`",
        b"local x = `unterminated",
        b"break",
        b"continue",
        b"local f = function() return ... end",
        b"return 1; print(2)",
        b"while true do break print(1) end",
        b"1 = 2",
        b"local x: = 3",
        b"local x: (number, string) = nil",
        b"local x: function = nil",
        b"local x: A... = nil",
        b"local x: ...number = nil",
        b"type T = A | B & C",
        b"local x = if true then 1",
        b"local x = {a = }",
        b"local x = function(,) end",
        b"--[=[unterminated",
    ];
    for source in cases {
        assert!(
            parse(source).is_err(),
            "unexpected success: {}",
            String::from_utf8_lossy(source)
        );
    }
    let err = parse(b"local a = 1\nlocal b = ").unwrap_err();
    assert_eq!(err.line, 2);
    assert!(err.column > 1);
}

#[test]
fn sample_is_parsed_without_execution() {
    let source = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/sample1.lua")).unwrap();
    let tree = parse(&source).unwrap();
    assert_eq!(tree.root.children.len(), 1);
    assert_eq!(tree.root.children[0].kind, Kind::Return);
}

#[test]
fn rejects_excessive_nesting_instead_of_unbounded_recursion() {
    let mut source = b"return ".to_vec();
    source.extend(std::iter::repeat(b'(').take(1200));
    source.extend(b"1");
    source.extend(std::iter::repeat(b')').take(1200));
    assert!(parse(&source).unwrap_err().message.contains("嵌套"));
}

#[test]
fn long_left_associative_expression_can_be_dropped() {
    let mut source = String::from("return 1");
    for _ in 0..10_000 {
        source.push_str(" + 1");
    }
    let tree = parse(source.as_bytes()).unwrap();
    let copy = tree.clone();
    assert_eq!(tree.root, copy.root);
    assert!(format!("{:?}", tree.root).contains("child_count"));
    drop(copy);
    drop(tree);
}

#[test]
fn deeply_nested_valid_expression_parses_on_small_caller_stack() {
    let handle = std::thread::Builder::new()
        .stack_size(128 * 1024)
        .spawn(|| {
            let source = format!("return {}1{}", "(".repeat(800), ")".repeat(800));
            let tree = parse(source.as_bytes()).unwrap();
            drop(tree);
        })
        .unwrap();
    handle.join().unwrap();
}

#[test]
fn attributes_type_packs_and_conditional_bindings() {
    let good = [
        "type F<T...> = (number, T...) -> (number, T...)",
        "type Foo = {['foo']: number, ['bar']: string, [string]: boolean}",
        "@[deprecated{use='new', reason='old'}] export function old() end",
        "local function f() return nil end; local x = if const y: number = f() then y else 0",
        "local f = function<T>() end; f<<>>()",
        "print()\x0bprint()",
        "local continue=print; continue \"hello\"; continue {}; continue<<number>>()",
        "@[native(`hello`)] local function f() end",
    ];
    for s in good {
        assert!(parse(s.as_bytes()).is_ok(), "{s}");
    }
    let bad = [
        "@wrong local function f() end",
        "@native @native local function f() end",
        "@[native(game)] function f() end",
        "@[deprecated{foo='a'}] function f() end",
        "@[deprecated{use=1}] function f() end",
        "@ native function f() end",
        "local x: {[string]: number, [number]: number}",
        "local x: {['\\0']: number}",
        "type F<T...> = (T..., number) -> ()",
        "type F<T...> = (number, T...) -> ...(T...)",
        "type F<T..., U> = U",
        "type F<T=number, U> = U",
        "type F = <T>number",
        "type F = nil.foo",
        "type F = nil<number>",
        "type F = typeof",
        "type F = {number, x: string}",
        "type F = ((number, string))",
        "type F = ((...number))",
        "local x: (B...?)",
        "type X = F<(A,B) | string>",
        "type F = number? & string",
        "local f = function<T=number>() end",
        "print `hello`",
        "print\n(1)",
        ";print(1)",
    ];
    for s in bad {
        assert!(parse(s.as_bytes()).is_err(), "{s}");
    }
}

#[test]
fn validates_constants_scope_closures_and_exports() {
    let good = [
        "local a=1; type function f() local a=2; return a end",
        "local a=1; type function f() return {a=2} end",
        "type function f() local a=1; local function g() return a end end",
        "const a=1; do local a=2; a=3 end",
        "const a=1; local a=a+1; a=2",
        "const a=1; function f(a) a=2 end",
        "const a=1; local function a() return a end; a=2",
        "const a={}; a.x=2; a[1]=3",
        "const a=1; for a=1,2 do a=2 end",
        "const a=1; for a in pairs({}) do a=2 end",
        "const self=1; function t:f() self=2 end",
        "const a,b=f(); return a,b",
        "export type A = number; return 1",
        "export local a,b=1,2; export function f() return a end",
        "if const x = 1 then print(x) end; x=2",
    ];
    let bad = [
        "local a=1; type function f() return a end",
        "local a=1; type function f() local a=a end",
        "local a=1; type function f() return t[a] end",
        "local a=1; type function f() local x: typeof(a) = nil end",
        "const a=1; local x: typeof(function() a=2 end) = nil",
        "const a=1; if local x: typeof(function() a=2 end) = 1 then end",
        "const a=1; for x: typeof(function() a=2 end) = 1,2 do end",
        "const a=1; for x: typeof(function() a=2 end) in pairs({}) do end",
        "local a=1; type function f() if local x: typeof(a) = 1 then end end",
        "const a=1; a=2",
        "const a=1; a+=1",
        "const a=1; function f() a=2 end",
        "const a=1; local a=function() a=2 end",
        "const a=1; function a() end",
        "const a=1; for i=1,2 do a=2 end",
        "const a=1; do a=2 end",
        "if const x = 1 then x=2 end",
        "const a,b=1",
        "const a",
        "export local function f() end",
        "export function a.b() end",
        "export local a=1; export local a=2",
        "export local a=1; return a",
        "if true then export local a=1 end",
    ];
    for s in good {
        assert!(parse(s.as_bytes()).is_ok(), "unexpected rejection: {s}");
    }
    for s in bad {
        assert!(parse(s.as_bytes()).is_err(), "unexpected success: {s}");
    }
}

#[test]
fn ast_preserves_important_declaration_and_field_distinctions() {
    let source = b"export type X = number; local t = {a=1, [a]=2, 3}; function t:go() end; for x,y in pairs(t) do end";
    let t = parse(source).unwrap();
    assert_eq!(t.root.children[0].kind, Kind::ExportTypeAlias);
    let table = find(&t.root.children[1], &|k| *k == Kind::Table).unwrap();
    assert_eq!(
        table.children.iter().map(|x| &x.kind).collect::<Vec<_>>(),
        vec![&Kind::TableRecord, &Kind::TableIndex, &Kind::TableArray]
    );
    assert_eq!(t.root.children[2].children[0].kind, Kind::MethodField);
    assert_eq!(t.root.children[3].children[0].kind, Kind::BindingList);
    assert_eq!(t.root.children[3].children[1].kind, Kind::ValueList);
}
