#!/bin/bash
# Go ↔ PHP 双向互通验证（修正：所有 sqlite3 用绝对路径）
set -u
DB=/opt/lab/pm2.0/data/passwords.db
export PATH=/opt/go/bin:$PATH GOPATH=/opt/gopath GOCACHE=/opt/gocache GOPROXY=https://goproxy.cn,direct

SALT=$(sqlite3 "$DB" "select master_key_salt from users;")
CIPHER=$(sqlite3 "$DB" "select cipher from passwords limit 1;")
echo "salt   = $SALT"
echo "cipher = ${CIPHER:0:36}..."

echo "--- Go 侧：派生的主密钥指纹（不打印密钥本身）---"
GOMK=$(cd /opt/lab/goproto && ./vault -salt "$SALT" -pw 'Master5678!xyz' -cipher "$CIPHER" | tee /tmp/go_out.txt | grep '主密钥指纹' | sed 's/.*: //')
echo "  $GOMK"

echo "--- PHP 侧：同一密码派生的主密钥（指纹应一致）---"
# PHP 侧同时算出指纹与密钥本体：
#   - 指纹用于比对（人工核对不需要看到密钥本身）
#   - 密钥本体仅在本脚本进程内变量中用于后续加解密，不回显
PHPMK=$(php -r 'require "/opt/lab/pm2.0/includes/config.php"; require "/opt/lab/pm2.0/includes/security.php";
$k = Security::deriveKey($argv[1], base64_decode($argv[2]), "pbkdf2", ["iterations"=>600000]);
echo $k["key"];' -- 'Master5678!xyz' "$SALT" 2>&1)
PHPMKFP=$(php -r 'echo substr(hash("sha256", base64_decode($argv[1])), 0, 8);' -- "$PHPMK" 2>&1)
echo "  $PHPMKFP"
if [ -n "$GOMK" ] && [ "$GOMK" = "$PHPMKFP" ]; then echo "  ==> 主密钥一致 ✓"; else echo "  ==> 不一致 ✗"; fi

GOCIPHER=$(grep '^GO_CIPHER=' /tmp/go_out.txt | cut -d= -f2-)
PHPCIPHER=$(php -r 'require "/opt/lab/pm2.0/includes/config.php"; require "/opt/lab/pm2.0/includes/security.php";
echo Security::encrypt("跨语言双向互通-Go", $argv[1]);' -- "$PHPMK" 2>&1)

echo
echo "--- 【A】PHP 解 Go 生成的密文 ---"
php -r 'require "/opt/lab/pm2.0/includes/config.php"; require "/opt/lab/pm2.0/includes/security.php";
try { echo "  明文 = ", Security::decrypt($argv[1], $argv[2]), "\n"; }
catch (Throwable $e) { echo "  失败: ", $e->getMessage(), "\n"; }' -- "$GOCIPHER" "$PHPMK" 2>&1

echo
echo "--- 【B】Go 解 PHP 生成的密文 ---"
cd /opt/lab/goproto && ./vault -salt "$SALT" -pw 'Master5678!xyz' -cipher "$PHPCIPHER" 2>&1 | grep -E '格式嗅探|解密结果'
