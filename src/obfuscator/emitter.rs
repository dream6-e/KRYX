// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use super::compiler::{Program, OP_COUNT};
use super::encode::encode85;
use super::seed::Random;

pub(super) fn opcode_mapping(rng: &mut Random) -> [u8; OP_COUNT] {
    let mut options: Vec<u8> = (1..=127).collect();
    rng.shuffle(&mut options);
    let mut result = [0; OP_COUNT];
    result.copy_from_slice(&options[..OP_COUNT]);
    result
}
fn quote_long(value: &str) -> String {
    let mut equals = String::from("=");
    while value.contains(&format!("]{equals}]")) {
        equals.push('=');
    }
    format!("[{equals}[{value}]{equals}]")
}
fn body(op: usize) -> &'static str {
    const BODIES: [&str; OP_COUNT] = [
        "f[g[J]]=K[s[J]];",
        "f[g[J]]=f[s[J]];",
        "f[g[J]]=f[s[J]]+f[W[J]];",
        "f[g[J]]=f[s[J]]-f[W[J]];",
        "f[g[J]]=f[s[J]]*f[W[J]];",
        "f[g[J]]=f[s[J]]/f[W[J]];",
        "f[g[J]]=f[s[J]]//f[W[J]];",
        "f[g[J]]=f[s[J]]%f[W[J]];",
        "f[g[J]]=f[s[J]]^f[W[J]];",
        "f[g[J]]=f[s[J]]..f[W[J]];",
        "f[g[J]]=f[s[J]]==f[W[J]];",
        "f[g[J]]=f[s[J]]~=f[W[J]];",
        "f[g[J]]=f[s[J]]<f[W[J]];",
        "f[g[J]]=f[s[J]]<=f[W[J]];",
        "f[g[J]]=f[s[J]]>f[W[J]];",
        "f[g[J]]=f[s[J]]>=f[W[J]];",
        "f[g[J]]=-f[s[J]];",
        "f[g[J]]=not f[s[J]];",
        "f[g[J]]=#f[s[J]];",
        "return g[J],s[J];",
        "f[g[J]]=H.print;",
        "f[g[J]](m[5](f,s[J],s[J]+W[J]-1));",
    ];
    BODIES[op]
}
fn dispatch(entries: &[(u8, usize)], rng: &mut Random) -> String {
    if entries.len() == 1 {
        let (id, op) = entries[0];
        return format!(
            "if C=={id} then {}else e.E('invalid opcode',0);end;",
            body(op)
        );
    }
    // Vary the comparison tree shape while preserving sorted dispatch intervals.
    let middle = if entries.len() <= 2 {
        1
    } else {
        1 + (rng.next() % (entries.len() as u64 - 1)) as usize
    };
    let pivot = entries[middle].0;
    format!(
        "if C<{pivot} then {}else {}end;",
        dispatch(&entries[..middle], rng),
        dispatch(&entries[middle..], rng)
    )
}
fn state_expr(value: u8, rng: &mut Random) -> String {
    let mask = rng.next() as u32;
    format!("e.G.bxor({mask},{})", mask ^ value as u32)
}

pub(super) fn emit(
    _program: &Program,
    data: &[u8],
    mapping: &[u8; OP_COUNT],
    rng: &mut Random,
) -> String {
    let payload = quote_long(&format!("LPH]{}", encode85(data)));
    let mut entries: Vec<_> = mapping
        .iter()
        .copied()
        .enumerate()
        .map(|(i, id)| (id, i))
        .collect();
    entries.sort_unstable();
    let tree = dispatch(&entries, rng);
    let mut states: Vec<u8> = (1..=127).collect();
    rng.shuffle(&mut states);
    let [a, b, c] = [states[0], states[1], states[2]];
    let initial = state_expr(a, rng);
    let to_b = state_expr(b, rng);
    let to_c = state_expr(c, rng);
    let mut clauses = vec![
        format!("n=={a} then m[20]=e:s();m[6]=1;m[39]=function()return e:le(m);end;n={to_b};"),
        format!("n=={b} then m[12]=m[39]();K=e:ee(m);q=e:i0(m);n={to_c};"),
        format!("n=={c} then e:g0(m,K);return m[45](q,{{}});"),
    ];
    rng.shuffle(&mut clauses);
    let bootstrap = format!(
        "if {}elseif {}elseif {}else e.E('invalid state',0);end;",
        clauses[0], clauses[1], clauses[2]
    );
    let mut fields = vec![
        "q=string".to_owned(), "G=bit32".to_owned(), "V=table.create".to_owned(),
        "C=pcall".to_owned(), "F=unpack".to_owned(), "E=error".to_owned(), "H=getfenv".to_owned(),
        format!("T={payload}"),
        // Five-character groups, a zero shortcut, and a cached __index table mirror the sample's encoding layer.
        "s=function(e)local n=e.q.sub(e.T,5);n=e.q.gsub(n,'z','!!!!!');return e.q.gsub(n,'.....',setmetatable({},{__index=function(t,O)local a,b,c,d,f=e.q.byte(O,1,5);local v=(a-33)*52200625+(b-33)*614125+(c-33)*7225+(d-33)*85+f-33;local x=e.q.pack('>I4',v);t[O]=x;return x;end}));end".to_owned(),
        "le=function(e,m)local v,k=0,1;repeat local b=e.q.byte(m[20],m[6]);m[6]+=1;v+=(b%128)*k;k*=128;until b<128;return v;end".to_owned(),
        "ee=function(e,m)local K={};local n=m[39]();for i=1,n do local t=m[39]();if t==1 then K[i]=false;elseif t==2 then K[i]=true;elseif t==3 then K[i]=m[39]();elseif t==4 then local z=m[39]();K[i]=e.q.sub(m[20],m[6],m[6]+z-1);m[6]+=z;end;end;return K;end".to_owned(),
        "i0=function(e,m)local q={[1]={},[3]={},[6]={},[10]={},[11]=m[12]};local count=m[39]();for i=1,count do q[6][i]=m[39]();q[1][i]=m[39]();q[3][i]=m[39]();q[10][i]=m[39]();end;return q;end".to_owned(),
        format!("g0=function(e,m,K)m[45]=function(q,t)local g,s,Q,W=q[1],q[3],q[6],q[10];return function(...)local f=m[13](q[11]);local H=e.H();local J=1;local ok,P,U=m[33](function()while true do local C=Q[J];{tree}J+=1;end;end);if not ok then e.E(P,0);end;if U==0 then return;end;return m[5](f,P,P+U-1);end;end;end"),
        format!("R0=function(e)local m={{[13]=e.V,[33]=e.C,[5]=e.F}};local n={initial};local K,q;while true do {bootstrap}end;end"),
    ];
    rng.shuffle(&mut fields);
    format!("return({{{}}}):R0()(...);\n", fields.join(","))
}
