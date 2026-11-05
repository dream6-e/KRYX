// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use super::{ObfuscationError, Result};

/// Draw a 16-digit decimal seed from the operating system, without a clock fallback.
pub fn generate() -> Result<u64> {
    const RANGE: u64 = 9_000_000_000_000_000;
    let limit = u64::MAX - u64::MAX % RANGE;
    loop {
        let mut bytes = [0; 8];
        os_random(&mut bytes).map_err(|e| ObfuscationError(format!("无法获取系统随机数：{e}")))?;
        let x = u64::from_le_bytes(bytes);
        if x < limit {
            return Ok(1_000_000_000_000_000 + x % RANGE);
        }
    }
}

#[cfg(unix)]
fn os_random(bytes: &mut [u8]) -> std::io::Result<()> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")?.read_exact(bytes)
}
#[cfg(windows)]
fn os_random(bytes: &mut [u8]) -> std::io::Result<()> {
    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(
            algorithm: *mut std::ffi::c_void,
            buffer: *mut u8,
            length: u32,
            flags: u32,
        ) -> i32;
    }
    // BCRYPT_USE_SYSTEM_PREFERRED_RNG; the buffer remains valid for this call.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            2,
        )
    };
    if status < 0 {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("BCryptGenRandom: {status}"),
        ))
    } else {
        Ok(())
    }
}
#[cfg(not(any(unix, windows)))]
fn os_random(_: &mut [u8]) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "不支持此平台的系统随机源",
    ))
}

/// SplitMix64 is deterministic; it randomizes layout, not cryptographic secrets.
pub(super) struct Random(u64);
impl Random {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut x = self.0;
        x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
        x ^ (x >> 31)
    }
    pub fn shuffle<T>(&mut self, values: &mut [T]) {
        for i in (1..values.len()).rev() {
            values.swap(i, (self.next() % (i as u64 + 1)) as usize);
        }
    }
}
