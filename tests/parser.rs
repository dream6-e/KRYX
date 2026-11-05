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
    let t = parse(b"type T = A | (B & C?)").unwrap();
    let union = find(&t.root, &|k| *k == Kind::TypeBinary("|".into())).unwrap();
    let intersection = find(&union.children[1], &|k| *k == Kind::TypeBinary("&".into())).unwrap();
    assert_eq!(intersection.children[1].kind, Kind::TypeOptional);
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
    source.extend(std::iter::repeat(b'(').take(250));
    source.extend(b"1");
    source.extend(std::iter::repeat(b')').take(250));
    assert!(parse(&source).unwrap_err().message.contains("嵌套"));
}

#[test]
fn long_left_associative_expression_can_be_dropped() {
    let mut source = String::from("return 1");
    for _ in 0..10_000 {
        source.push_str(" + 1");
    }
    let tree = parse(source.as_bytes()).unwrap();
    drop(tree);
}
