set -u
B=http://127.0.0.1:8099
J=/tmp/cj2.txt
rm -f $J
CSRF=$(curl -sS --noproxy '*' -c $J "$B/index.php" | grep -o "RECOVERY_CSRF = '[a-f0-9]*'" | grep -o "[a-f0-9]\{64\}")
echo -n "登录: "; curl -sS --noproxy '*' -b $J -c $J -X POST "$B/api/auth.php" \
  -d "action=login&username=tester&password=Test1234!abc" | head -c 40; echo

curl -sS --noproxy '*' -b $J -c $J "$B/main.php" -o /dev/null
CSRF=$(curl -sS --noproxy '*' -b $J -c $J "$B/main.php" | grep -o "CSRF_TOKEN = '[a-f0-9]*'" | grep -o "[a-f0-9]\{64\}")

echo -n "解锁主密钥: "
curl -sS --noproxy '*' -b $J -c $J -X POST "$B/api/auth.php" \
  -d "action=verify_master_key&password=Master5678!xyz&csrf_token=$CSRF" -o /tmp/mk2.json -w "HTTP=%{http_code}\n"
head -c 60 /tmp/mk2.json; echo

echo -n "加密码: "; curl -sS --noproxy '*' -b $J -c $J -X POST "$B/api/passwords.php" \
  -d "action=add&title=GitHub&url=https://github.com&username=demo@x.com&password=MyStr0ng!Pass&category_id=1&csrf_token=$CSRF"; echo

echo "--- 供 Go/Rust 互通验证的数据 ---"
sqlite3 /opt/lab/pm2.0/data/passwords.db "select 'SALT='||master_key_salt from users;"
sqlite3 /opt/lab/pm2.0/data/passwords.db "select 'KDF='||kdf_type||' '||kdf_params from users;"
sqlite3 /opt/lab/pm2.0/data/passwords.db "select 'CIPHER='||cipher from passwords limit 1;"
sqlite3 /opt/lab/pm2.0/data/passwords.db "select 'PLAIN_EXPECT=MyStr0ng!Pass';"
