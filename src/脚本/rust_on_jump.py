#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""跳板机：编译 Rust 原型（含 KDF 基准），并做 Rust↔PHP 互通验证。"""
import socket
import sys

import paramiko
from pathlib import Path

HOST = "example-jump-host"
KEY = str(Path.home() / ".ssh" / "id_workbuddy")
ENV = ("export RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH; "
       "export CARGO_HTTP_MULTIPLEXING=false;")
MIRROR = """
mkdir -p /opt/cargo
cat > /opt/cargo/config.toml <<'EOF'
[source.crates-io]
replace-with = 'tuna'

[source.tuna]
registry = "sparse+https://mirrors.tuna.tsinghua.edu.cn/crates.io-index/"
EOF
echo mirror-ok
"""


def run(cli, cmd, timeout=300, label=""):
    _in, out, err = cli.exec_command(cmd, timeout=timeout)
    try:
        body = out.read().decode("utf-8", "replace")
    except socket.timeout:
        body = "[timeout]"
    try:
        errs = err.read().decode("utf-8", "replace")
    except socket.timeout:
        errs = ""
    if label:
        print(f"--- {label} ---")
    if body.strip():
        print(body.strip()[:1600])
    if errs.strip():
        print(f"[stderr] {errs.strip()[:400]}")
    return body


def main() -> int:
    cli = paramiko.SSHClient()
    cli.load_system_host_keys()
    cli.set_missing_host_key_policy(paramiko.WarningPolicy())
    cli.connect(hostname=HOST, port=22, username="root", key_filename=KEY,
                timeout=15, banner_timeout=20, auth_timeout=20,
                allow_agent=False, look_for_keys=False)

    sftp = cli.open_sftp()
    cli.exec_command("mkdir -p /opt/lab/rustproto/src")[1].read()
    for local, remote in [
        (r"C:\Users\Administrator\AppData\Local\Temp\rustproto\Cargo.toml", "/opt/lab/rustproto/Cargo.toml"),
        (r"C:\Users\Administrator\AppData\Local\Temp\rustproto\src\main.rs", "/opt/lab/rustproto/src/main.rs"),
        (r"C:\Users\Administrator\AppData\Local\Temp\rustproto\src\bench.rs", "/opt/lab/rustproto/src/bench.rs"),
    ]:
        try:
            with sftp.open(remote, "wb") as fh:
                fh.write(open(local, "rb").read())
        except FileNotFoundError:
            print(f"[缺失] {local}")
    sftp.close()

    run(cli, MIRROR, 60, "配置 crates 镜像")
    run(cli, f"{ENV} cd /opt/lab/rustproto && cargo build --release --bins 2>&1 | tail -8", 600, "编译")
    run(cli, "ls -la /opt/lab/rustproto/target/release/ | grep -E 'vault_proto|bench'", 30, "产物")

    print("\n=== Rust KDF 基准（Ubuntu 8 核）===")
    run(cli, f"{ENV} cd /opt/lab/rustproto && ./target/release/bench 2>&1", 120)

    print("\n=== Rust ↔ PHP 互通 ===")
    xfer = """
set -u
DB=/opt/lab/pm2.0/data/passwords.db
SALT=$(sqlite3 "$DB" "select master_key_salt from users;")
CIPHER=$(sqlite3 "$DB" "select cipher from passwords limit 1;")
export RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
cd /opt/lab/rustproto
echo "--- Rust 解 PHP 密文 ---"
VAULT_SALT="$SALT" VAULT_PW='Master5678!xyz' ./target/release/vault_proto "$CIPHER" 2>&1 | grep -E '格式嗅探|派生的主密钥|解密结果|回环|Argon2id'
PHPMK=$(php -r 'require "/opt/lab/pm2.0/includes/config.php"; require "/opt/lab/pm2.0/includes/security.php";
$k = Security::deriveKey($argv[1], base64_decode($argv[2]), "pbkdf2", ["iterations"=>600000]);
echo $k["key"];' -- 'Master5678!xyz' "$SALT" 2>&1)
RUSTC=$(VAULT_SALT="$SALT" VAULT_PW='Master5678!xyz' ./target/release/vault_proto "$CIPHER" 2>&1 | grep '^RUSTCIPHER=' | cut -d= -f2-)
echo "--- PHP 解 Rust 密文 ---"
php -r 'require "/opt/lab/pm2.0/includes/config.php"; require "/opt/lab/pm2.0/includes/security.php";
try { echo "  明文 = ", Security::decrypt($argv[1], $argv[2]), "\\n"; }
catch (Throwable $e) { echo "  失败: ", $e->getMessage(), "\\n"; }' -- "$RUSTC" "$PHPMK" 2>&1
"""
    sftp = cli.open_sftp()
    with sftp.open("/tmp/xfer.sh", "w") as fh:
        fh.write(xfer)
    sftp.close()
    run(cli, "bash /tmp/xfer.sh 2>&1", 180)
    cli.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
