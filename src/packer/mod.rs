// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
pub mod utils;
pub mod compressor;
pub mod encryptor;
pub mod stub_generator;

pub fn pack_lua(input: &str) -> String {
    let compressed = compressor::Compressor::compress(input.as_bytes());
    let (encrypted, keys) = encryptor::Encryptor::xor_stream(&compressed);
    let (payload, alphabet) = encryptor::Encryptor::base122_encode(&encrypted);
    stub_generator::StubGenerator::build_decoder(&payload, &keys, &alphabet)
}