set -u
B=http://127.0.0.1:8099
J=/tmp/cj.txt
rm -f $J
p() { echo; echo "### $1"; }

p "0. 环境"
php -v | head -1
php -m | grep -E '^(openssl|pdo_sqlite|sqlite3|sodium)$' | tr '\n' ' '; echo
echo -n "  库内用户数: "; sqlite3 /opt/lab/pm2.0/data/passwords.db "select count(*) from users;" 2>/dev/null || echo "无库"

p "1. 首页渲染"
curl -sS --noproxy '*' -c $J "$B/index.php" -o /tmp/i.html -w "HTTP=%{http_code} size=%{size_download}\n"
grep -o '<title>[^<]*</title>' /tmp/i.html
CSRF=$(curl -sS --noproxy '*' -b $J -c $J "$B/index.php" | grep -o "RECOVERY_CSRF = '[a-f0-9]*'" | grep -o "[a-f0-9]\{64\}")
echo "CSRF=${CSRF:0:16}..."

p "2. 注册主账户（全新库）"
curl -sS --noproxy '*' -b $J -c $J -X POST "$B/api/auth.php" \
  -d "action=register&username=tester&password=Test1234!abc&master_key_password=Master5678!xyz&csrf_token=$CSRF"

p "3. 登录 + 观察实际写入的 KDF 参数"
curl -sS --noproxy '*' -b $J -c $J -X POST "$B/api/auth.php" -d "action=login&username=tester&password=Test1234!abc" \
 | grep -o '"kdf_type":"[a-z0-9]*","kdf_params":"[^"]*"'
curl -sS --noproxy '*' -b $J -c $J "$B/main.php" -o /dev/null
CSRF=$(curl -sS --noproxy '*' -b $J -c $J "$B/main.php" | grep -o "CSRF_TOKEN = '[a-f0-9]*'" | grep -o "[a-f0-9]\{64\}")

p "4. 主密钥解锁（计时 ×2）"
for i in 1 2; do
  curl -sS --noproxy '*' -b $J -c $J -X POST "$B/api/auth.php" \
    -d "action=verify_master_key&password=Master5678!xyz&csrf_token=$CSRF" \
    -o /tmp/mk.json -w "  解锁#$i 耗时 %{time_total}s\n"
done
MK=$(grep -o '"master_key":"[^"]*"' /tmp/mk.json | cut -d'"' -f4)
echo "  主密钥=${MK:0:16}...  (长度 ${#MK})"

p "5. 建分类 + 加密码 + 解密回读"
curl -sS --noproxy '*' -b $J -c $J -X POST "$B/api/categories.php" \
  -d "action=add&name=开发工具&icon=laptop&parent_id=0&csrf_token=$CSRF" | head -c 100; echo
curl -sS --noproxy '*' -b $J -c $J -X POST "$B/api/passwords.php" \
  -d "action=add&title=GitHub&url=https://github.com&username=demo@x.com&password=MyStr0ng!Pass&category_id=1&csrf_token=$CSRF"
echo
ENC_MK=$(php -r 'echo urlencode($argv[1]);' -- "$MK")
echo -n "  解密回读: "
curl -sS --noproxy '*' -b $J -c $J -X POST "$B/api/passwords.php" \
  -d "action=decrypt&id=1&master_key=$ENC_MK&csrf_token=$CSRF"

p "6. 备份 + 还原完整性校验"
curl -sS --noproxy '*' -b $J -c $J -X POST "$B/api/backup.php" -d "action=backup&csrf_token=$CSRF" | head -c 170; echo

p "7. 【缺陷实测】恢复密钥 -> 改主密钥 -> 恢复密钥是否仍可用"
RKJSON=$(curl -sS --noproxy '*' -b $J -c $J -X POST "$B/api/auth.php" \
  -d "action=generate_recovery_key&password=Master5678!xyz&csrf_token=$CSRF")
RK=$(echo "$RKJSON" | grep -o '"recovery_key":"[^"]*"' | cut -d'"' -f4)
echo "  生成恢复密钥: $RK"
echo -n "  改主密钥结果: "
curl -sS --noproxy '*' -b $J -c $J -X POST "$B/api/auth.php" \
  -d "action=change_master_key&old_password=Master5678!xyz&new_password=NewMaster9999!abc&confirm_password=NewMaster9999!abc&csrf_token=$CSRF" \
  | head -c 100; echo
echo -n "  改后 verify_recovery_key : "
curl -sS --noproxy '*' -b $J -c $J -X POST "$B/api/auth.php" \
  -d "action=verify_recovery_key&username=tester&recovery_key=$RK&csrf_token=$CSRF"; echo
echo -n "  改后 recover（应能救回） : "
curl -sS --noproxy '*' -b $J -c $J -X POST "$B/api/auth.php" \
  -d "action=recover&username=tester&recovery_key=$RK&new_password=Reset1234!abc&new_master_password=ResetMaster!abc&confirm_master_password=ResetMaster!abc&csrf_token=$CSRF"; echo
echo -n "  救回后库内 kdf_params    : "
sqlite3 /opt/lab/pm2.0/data/passwords.db "select kdf_type||' '||kdf_params from users;"

p "8. 【缺陷实测】KDF 是否真的用上 Argon2id"
php -r '
require "/opt/lab/pm2.0/includes/config.php";
require "/opt/lab/pm2.0/includes/security.php";
echo "  sodium 已加载            : ", extension_loaded("sodium") ? "YES" : "NO", "\n";
echo "  bestKdfType() 实际返回   : ", Security::bestKdfType(), "   <- 应为 argon2id\n";
echo "  CONST ..._ALG_ARGON2ID   : ", defined("SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID") ? "存在" : "不存在（代码写错名）", "\n";
echo "  CONST ..._ALG_ARGON2ID13 : ", defined("SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13") ? "存在" : "不存在", "\n";
'

p "9. 【缺陷实测】外键是否启用 + 级联是否生效"
php -r '
require "/opt/lab/pm2.0/includes/database.php";
$db = Database::getInstance();
$r = $db->fetchOne("PRAGMA foreign_keys");
echo "  PRAGMA foreign_keys = ", $r["foreign_keys"], "  (1=开 0=关)\n";
'
echo -n "  删除用户后残留密码条数: "
sqlite3 /opt/lab/pm2.0/data/passwords.db "PRAGMA foreign_keys=ON; delete from users; select count(*) from passwords;"
echo "  （SQLite 默认关外键 => 上面是非级联结果）"

p "10. 【缺陷实测】isEncryptedCipher 误判"
php -r '
require "/opt/lab/pm2.0/includes/database.php";
require "/opt/lab/pm2.0/includes/security.php";
$t = ["c29tZSByYW5kb20gcGFzc3dvcmQgdGhhdCBpcyBsb25n" => "合法base64的明文口令",
      "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0NTY3OA==" => "合法base64+padding",
      "correct horse battery staple" => "普通英文短语"];
foreach ($t as $s => $l) {
  printf("  %-26s len=%-3d => %s\n", $l, strlen($s),
    Security::isEncryptedCipher($s) ? "TRUE (误判为密文!)" : "false");
}
'

p "11. PBKDF2 600k / Argon2id 在 Ubuntu 实测耗时"
php -r '
for ($i=0;$i<3;$i++){
  $t=microtime(true);
  hash_pbkdf2("sha256","Master5678!xyz",random_bytes(16),600000,32,true);
  printf("  PBKDF2-600k                    : %.0f ms\n",(microtime(true)-$t)*1000);
}
for ($i=0;$i<3;$i++){
  $t=microtime(true);
  sodium_crypto_pwhash(32,"Master5678!xyz",random_bytes(16),2,67108864,SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
  printf("  sodium Argon2id(m=64M,ops=2)   : %.0f ms\n",(microtime(true)-$t)*1000);
}
'

p "12. 【部署风险实测】PHP 内置服务器下敏感文件可达性"
curl -sS --noproxy '*' -o /dev/null -w "  /data/passwords.db   => HTTP %{http_code}\n" "$B/data/passwords.db"
curl -sS --noproxy '*' -o /dev/null -w "  /includes/config.php => HTTP %{http_code}\n" "$B/includes/config.php"
echo "  （php -S 不读 .htaccess；说明仅用内置服务器时数据库可被直接下载）"

echo; echo "### 测试结束"
