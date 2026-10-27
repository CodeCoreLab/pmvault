#!/bin/bash
# Rust ↔ PHP 双向互通验证（Ubuntu 跳板机）
set -u
DB=/opt/lab/pm2.0/data/passwords.db
export RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH

SALT=$(sqlite3 "$DB" "select master_key_salt from users;")
CIPHER=$(sqlite3 "$DB" "select cipher from passwords limit 1;")
echo "salt=$SALT"
echo "cipher=${CIPHER:0:36}..."

cd /opt/lab/rustproto
OUT=$(VAULT_SALT="$SALT" VAULT_PW='Master5678!xyz' ./target/release/vault_proto "$CIPHER" 2>&1)
echo "$OUT" | grep -E '格式嗅探|派生的主密钥|解密结果|自解密回环|Argon2id'
RUSTMK=$(echo "$OUT" | grep '派生的主密钥' | sed 's/.*: //')
RUSTC=$(echo "$OUT" | grep '^RUSTCIPHER=' | cut -d= -f2-)

PHPMK=$(php -r 'require "/opt/lab/pm2.0/includes/config.php"; require "/opt/lab/pm2.0/includes/security.php";
$k = Security::deriveKey($argv[1], base64_decode($argv[2]), "pbkdf2", ["iterations"=>600000]);
echo $k["key"];' -- 'Master5678!xyz' "$SALT" 2>&1)
echo "PHP 派生主密钥 = $PHPMK"
[ "$RUSTMK" = "$PHPMK" ] && echo "==> Rust 与 PHP 主密钥一致 ✓" || echo "==> 不一致 ✗"

echo
echo "--- PHP 解 Rust 生成的密文 ---"
php -r 'require "/opt/lab/pm2.0/includes/config.php"; require "/opt/lab/pm2.0/includes/security.php";
try { echo "  明文 = ", Security::decrypt($argv[1], $argv[2]), "\n"; }
catch (Throwable $e) { echo "  失败: ", $e->getMessage(), "\n"; }' -- "$RUSTC" "$PHPMK" 2>&1
