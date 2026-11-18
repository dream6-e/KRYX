// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
pub fn build_vm_core() -> String {
    let mut core = String::new();
    core.push_str("local A, B, C, D = ...;\n");
    core.push_str("local function E(F, G, H)\n");
    core.push_str("local state, I, J, K, L, M, N = 0, F[G], F[H], 1, 0, nil, nil;\n");
    core.push_str("while state ~= 3 do\n");
    core.push_str("if state == 0 then if I > 0 and J > 0 then M, N = I % 2, J % 2; if M ~= N then L = L + K end; I, J, K = (I - M) / 2, (J - N) / 2, K * 2; else state = 1 end\n");
    core.push_str("elseif state == 1 then if I < J then I = J end; state = 2\n");
    core.push_str("elseif state == 2 then if I > 0 then M = I % 2; if M > 0 then L = L + K end; I, K = (I - M) / 2, K * 2 else state = 3 end end end\n");
    core.push_str("return L end\n");
    core.push_str("local function O(P, Q, R)\n");
    core.push_str("local S, T, U, r, K, V, W, X, Y, Z = {}, 1, 1, 0.9, Q, nil, nil, nil, nil, nil;\n");
    core.push_str("while T <= #P do\n");
    core.push_str("V, W = string_byte(P, T, T), K[U];\n");
    core.push_str("Y = (T * 13) % 256; Z = (W + Y) % 256;\n");
    core.push_str("X = (function(a_, b_) return E({a_, b_}, 1, 2) end)(V, Z);\n");
    core.push_str("if math_random() < r then S[T] = string_char(X) else S[T] = string_char(X) end;\n");
    core.push_str("K[U] = (K[U] + V + Y + 7) % 256;\n");
    core.push_str("K[U] = (K[U] * 5 + 1) % 256;\n");
    core.push_str("T, U = T + 1, (U % #Q) + 1;\n");
    core.push_str("end\n");
    core.push_str("return table_concat(S) end\n");
    core
}
