//! 迁移可行性验证原型：用 Rust 读取 PHP 版密码管理器 2.0 产生的密文
//!
//! 目标：证明「PHP v3 格式密文 + PBKDF2 派生主密钥」可以被 Rust 完全等价复现，
//! 从而使「重写后端但不丢历史数据」成为可执行方案而非纸面设想。

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};

const V3: u8 = 0x03;
const V2: u8 = 0x02;

/// 派生密钥的指纹（sha256 前 8 位十六进制）。
///
/// 【为什么不能打印密钥本身】主密钥是解密一切历史数据的关键材料，
/// 把它打到 stdout 会落进终端回滚缓冲 / CI 日志 / 截图 / 输出重定向文件。
/// 人工核对「两侧派生出的是不是同一个密钥」只需要一个指纹就够了。
fn key_fingerprint(key: &[u8]) -> String {
    let digest = Sha256::digest(key);
    digest.iter().map(|b| format!("{b:02x}")).collect::<String>()[..8].to_string()
}

/// 展示用的派生密钥摘要行：只含指纹，绝不含密钥本身。
fn key_summary(label: &str, key: &[u8]) -> String {
    format!("{label}: {}", key_fingerprint(key))
}

/// 与 PHP 相同的 KDF：PBKDF2-HMAC-SHA256
fn derive_key_pbkdf2(password: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut key);
    key
}

/// 与 PHP 相同的 Argon2id 派生（libsodium: opslimit=2, memlimit=64MB）
/// sodium 的 opslimit/memlimit 与 argon2 crate 的 m/t 参数需换算，这里给出等价映射。
fn derive_key_argon2id(password: &str, salt: &[u8], mem_kib: u32, iterations: u32) -> [u8; 32] {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(mem_kib, iterations, 1, Some(32)).expect("argon2 params");
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    a2.hash_password_into(password.as_bytes(), salt, &mut out)
        .expect("argon2 derive");
    out
}

/// 解析并解密 PHP v3 格式：base64( 0x03  IV(12)  Tag(16)  Ciphertext )
fn decrypt_v3(blob_b64: &str, key: &[u8; 32]) -> Result<String, String> {
    let data = B64.decode(blob_b64.trim()).map_err(|e| format!("base64 解码失败: {e}"))?;
    if data.len() < 29 {
        return Err(format!("数据过短: {} 字节", data.len()));
    }
    if data[0] != V3 {
        return Err(format!("版本字节不符: 期望 0x03, 实际 0x{:02x}", data[0]));
    }
    let iv = &data[1..13];
    let tag = &data[13..29];
    let ct = &data[29..];

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("建 cipher 失败: {e}"))?;
    // aes-gcm 的 decrypt 需要 "ciphertext  tag" 拼接
    let mut combined = Vec::with_capacity(ct.len() + tag.len());
    combined.extend_from_slice(ct);
    combined.extend_from_slice(tag);

    let plain = cipher
        .decrypt(Nonce::from_slice(iv), combined.as_ref())
        .map_err(|_| "GCM 认证失败（密钥错误或数据被篡改）".to_string())?;
    String::from_utf8(plain).map_err(|e| format!("明文非 UTF-8: {e}"))
}

/// 加密成 PHP v3 格式，用于验证「Rust 写的密文 PHP 也能读」的双向兼容
fn encrypt_v3(plain: &str, key: &[u8; 32]) -> Result<String, String> {
    use rand::RngCore;
    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut iv);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("建 cipher 失败: {e}"))?;
    let sealed = cipher
        .encrypt(Nonce::from_slice(&iv), plain.as_bytes())
        .map_err(|_| "GCM 加密失败".to_string())?;
    // sealed = ciphertext  tag(16)
    let split = sealed.len() - 16;
    let (ct, tag) = sealed.split_at(split);
    let mut blob = Vec::with_capacity(1 + 12 + 16 + ct.len());
    blob.push(V3);
    blob.extend_from_slice(&iv);
    blob.extend_from_slice(tag);
    blob.extend_from_slice(ct);
    Ok(B64.encode(blob))
}

/// 简化版 v2（CBC+HMAC）标识检测，仅用于说明三格式识别的可移植性
fn sniff_format(blob_b64: &str) -> &'static str {
    match B64.decode(blob_b64.trim()) {
        Ok(d) if !d.is_empty() => match (d[0], d.len()) {
            (V3, n) if n >= 29 => "v3 (AES-256-GCM + 版本前缀)",
            (V2, n) if n >= 49 => "v2 (AES-256-CBC + HMAC-SHA256)",
            _ => "legacy (无前缀 GCM) 或需回退尝试",
        },
        _ => "非法 base64",
    }
}

fn main() {
    let salt_b64 = std::env::var("VAULT_SALT").unwrap_or_else(|_| "R8wK0u9p6uwNKIqNc370hQ==".to_string());
    let password = std::env::var("VAULT_PW").unwrap_or_else(|_| "NewMaster9999!abc".to_string());
    let cipher_v3 = std::env::args().nth(1).expect("用法: vault_proto <cipher_base64>");

    let salt = B64.decode(salt_b64).expect("salt");
    println!("格式嗅探      : {}", sniff_format(&cipher_v3));
    println!("salt 长度     : {} 字节", salt.len());

    let key = derive_key_pbkdf2(&password, &salt, 600_000);
    // 只打印指纹，不打印派生主密钥本身（见 key_fingerprint 的说明）。
    println!("{}", key_summary("主密钥指纹(sha256前8位)", &key));

    match decrypt_v3(&cipher_v3, &key) {
        Ok(plain) => {
            println!("解密结果      : {plain:?}   <== 与 PHP 一致即证明互通");
            let round = encrypt_v3(&plain, &key).expect("encrypt");
            println!("RUSTCIPHER={}", round);
            let back = decrypt_v3(&round, &key).expect("roundtrip");
            println!("自解密回环    : {:?}  {}", back, if back == plain { "OK" } else { "FAIL" });
        }
        Err(e) => println!("解密失败      : {e}"),
    }

    let a2key = derive_key_argon2id(&password, &salt, 65536, 2);
    println!("Argon2id 指纹  : {}", key_fingerprint(&a2key));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 验证摘要行不含密钥材料本身（修复前原型直接打印 base64 主密钥）。
    #[test]
    fn key_summary_contains_no_key_material() {
        let key = b"0123456789abcdef0123456789abcdef";
        let line = key_summary("主密钥指纹(sha256前8位)", key);

        assert!(!line.contains(&B64.encode(key)), "摘要行含 base64 密钥: {line}");
        assert!(!line.contains(std::str::from_utf8(key).unwrap()), "摘要行含密钥原始字节: {line}");
        assert!(line.contains(&key_fingerprint(key)), "摘要行应含指纹: {line}");
    }

    /// 验证指纹稳定、长度固定为 8 位小写十六进制，且能区分不同密钥。
    #[test]
    fn key_fingerprint_is_stable_and_distinguishing() {
        let k1 = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let k2 = b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        assert_eq!(key_fingerprint(k1), key_fingerprint(k1));
        assert_ne!(key_fingerprint(k1), key_fingerprint(k2));

        for k in [k1, k2] {
            let fp = key_fingerprint(k);
            assert_eq!(fp.len(), 8, "指纹长度应为 8: {fp}");
            assert!(fp.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        }
    }

    /// 验证派生出的主密钥确实不出现在摘要里（黑盒等价：跑一遍真实派生）。
    #[test]
    fn derived_master_key_not_leaked_by_summary() {
        let salt = B64.decode("R8wK0u9p6uwNKIqNc370hQ==").unwrap();
        let key = derive_key_pbkdf2("Master5678!xyz", &salt, 1000);
        let line = key_summary("主密钥指纹(sha256前8位)", &key);

        assert!(!line.contains(&B64.encode(key)), "摘要行含派生主密钥: {line}");
        assert!(line.contains(&key_fingerprint(&key)));
    }
}

