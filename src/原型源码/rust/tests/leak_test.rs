//! 黑盒回归测试：验证原型运行时 stdout 不含派生主密钥明文。
//!
//! 放在独立集成测试里（而不是 main.rs 的单元测试里）是有意的：
//! 本测试只用「跑一次二进制 → 检查 stdout」的方式验证，
//! 不引用二进制 crate 内的任何符号，因此**同一份测试代码**
//! 在「缺陷版本」（直接打印 base64 主密钥）与「修复版本」下都能编译运行，
//! 可以直接用于「缺陷版本失败 / 修复后通过」的双向验证。

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::process::Command;

const TEST_SALT_B64: &str = "R8wK0u9p6uwNKIqNc370hQ==";
const TEST_PASSWORD: &str = "Master5678!xyz";

/// 复现 PHP hash_pbkdf2('sha256', pw, salt, iterations, 32, true)。
fn pbkdf2_key(password: &str, salt: &[u8], iterations: u32) -> Vec<u8> {
    let mut key = vec![0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut key);
    key
}

#[test]
fn stdout_has_no_derived_master_key() {
    let salt = B64.decode(TEST_SALT_B64).unwrap();

    // 密文参数给一个非法值：原型会在打印派生信息后走到解密失败分支，
    // 我们只关心前半段 stdout 里有没有泄漏密钥。
    let out = Command::new(env!("CARGO_BIN_EXE_vault_proto"))
        .arg("not-a-valid-cipher")
        .env("VAULT_SALT", TEST_SALT_B64)
        .env("VAULT_PW", TEST_PASSWORD)
        .output()
        .expect("运行原型失败");
    let stdout = String::from_utf8_lossy(&out.stdout);

    let key_b64 = B64.encode(pbkdf2_key(TEST_PASSWORD, &salt, 600_000));
    assert!(
        !stdout.contains(&key_b64),
        "stdout 含派生主密钥明文:\n{stdout}"
    );
    assert!(
        !stdout.contains(key_b64.trim_end_matches('=')),
        "stdout 含派生主密钥明文（无 padding 变体）:\n{stdout}"
    );
}
