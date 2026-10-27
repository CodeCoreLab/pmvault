# pmvault — 密码管理器

Windows 本地单机密码保险箱。AES-256-GCM 认证加密 + Argon2id 密钥派生，
主密钥不落盘、明文不出进程；仅监听回环地址，闲置 15 分钟自动上锁。
单文件 exe，双击即用，无需安装与联网。

| 项 | 值 |
|---|---|
| 技术栈 | Go（后端，静态编译）+ 原生 JS 前端 |
| 前端承载 | 浏览器版：默认浏览器；桌面版：Edge/Chrome `--app` 模式独立窗口 |
| 运行平台 | Windows 10/11（桌面版依赖系统已装 Edge 或 Chrome） |

## 目录

```
pmvault/
├── src/                          源码与验收脚本
│   ├── phase-a/                  浏览器版（Go，Subsystem=2）
│   ├── phase-edgeapp/            桌面版（Go，-H windowsgui，Edge/Chrome 承载）
│   ├── 原型源码/                 早期 Go / Rust 原型
│   ├── 跨平台编译/               跨平台构建实验
│   ├── 脚本/                     辅助脚本目录
│   └── 脚本-*.py                 图标生成、双包验收、UI 端到端验收、macOS 打包
├── releases/                     发布的 zip 包
└── docs/                         产品页 + 设计与评估报告
```

## 制品

| 文件 | 大小 | 说明 |
|---|---|---|
| `releases/密码管理器-原生窗口版-Windows.zip` | 4.14 MB | 独立窗口，推荐日常使用 |
| `releases/密码管理器-桌面版-Windows.zip` | 4.15 MB | 浏览器承载界面 |

> 制品文件名沿用历史命名（"原生窗口版" 实为 Edge/Chrome `--app` 模式承载，
> 并非原生 Win32 控件渲染）。后续重新打包时建议统一为「桌面版」。
>
> macOS 侧由 `src/脚本-打包-macOS.py` 产出 `.app` bundle，不走 Windows 打包脚本。

两包均**无 bat 启动脚本**，双击 exe 直接启动（PE Subsystem=2，无控制台），
且 exe 已链入程序图标（7 种尺寸）。

## 安全参数（源码核实）

```
对称加密    AES-256-GCM
密文结构    0x03 ‖ IV(12) ‖ Tag(16) ‖ CT
主密钥派生  Argon2id，内存 64 MiB，迭代 2，并行 1
口令哈希    Argon2id，内存 64 MiB，迭代 4，并行 1（PHC 字符串格式）
主密钥      不落盘，仅进程内存
监听        127.0.0.1（随机端口）
自动上锁    闲置 15 分钟（滑动窗口：每次成功操作续期）；会话 30 分钟
登录限流    按来源 IP 10 次/分，按用户名 5 次/5 分（用户名归一化为小写）
账户锁定    连续 5 次失败锁定 15 分钟（锁定时间以 UTC 存储）
备份轮转    保留最近 30 份
错误响应    对外只返回稳定错误码 + 中文文案，底层错误仅写日志
```

### 关于 KDF 参数

主密钥派生与口令哈希使用**不同的迭代次数**，这是有意为之：

- 主密钥（`ops=2`）：只在解锁时计算一次，且需与历史 PHP 版数据逐字节兼容，
  参数被 PHP 版的 `opslimit` 语义固定，不能随意提高。
- 口令哈希（`t=4`）：仅在登录时对用户输入的密码做一次哈希校验，
  不需要跨实现兼容，可以取更高迭代数以抵抗离线爆破。

调高主密钥派生参数会导致**旧数据无法解密**，属于破坏性变更，不可轻易调整。

## 重新构建

```bash
# 生成图标资源（.ico + .syso，两版共用）
# 路径参数可省略，脚本默认输出到 phase-edgeapp/cmd/vaultgui
python src/脚本-生成图标.py

# 打包（各自目录内有 脚本-打包.py）
cd src/phase-edgeapp && python 脚本-打包.py
cd src/phase-a      && python 脚本-打包.py

# macOS 打包（产出 .app bundle，需在 macOS 上执行）
cd src && python 脚本-打包-macOS.py
```

依赖 Go 1.23+ 工具链。若 `go` 不在 PATH 中，请把 Go 安装目录的 `bin`
加入 PATH（例如 `C:\Program Files\Go\bin`），或在 `脚本-打包.py` 中
通过 `GO` 环境变量指定 `go.exe` 的完整路径。

> 所有脚本的路径均**基于脚本自身位置解析**，不含硬编码绝对路径——
> 整个目录搬到任何位置都能直接跑。

### 依赖管理

```bash
cd src/phase-a
go mod tidy        # 同步 go.mod / go.sum
go build ./...
go vet ./...
go test ./...
```

`go mod tidy` 会补齐 `github.com/google/uuid` 等 indirect 依赖，
请在提交前确保 `go.mod` 与 `go.sum` 一起更新。

## 验收

```bash
# 双包纯 exe 验收：解压 → 双击即用 → 注册/增删/解密/CSRF/备份 → 落盘核对 → 退出
python src/脚本-验收双包.py
# UI 端到端：真实点击 UI，含 CSP 违规与密码明文遮蔽检查
python src/脚本-验收UI.py
# 产品页视觉验收：区块完整性、栅格列数、横向溢出、移动端布局
python src/脚本-验收产品页.py
```

三个脚本在结尾会打印**检查项总数与失败项清单**，退出码非 0 即失败，可直接接入 CI。

### 单元测试

```bash
cd src/phase-a       && go test ./...
cd src/phase-edgeapp && go test ./...
```

两个模块各 17 项，覆盖会话并发访问、闲置上锁、错误码脱敏、限流窗口、账户锁定时间解析、
加解密往返等核心行为。如本机装有 gcc，可加 `-race` 参数做数据竞争检测：

```bash
CGO_ENABLED=1 go test -race ./internal/vault/
```

## 目录约定

```
pmvault/
├── src/
│   ├── phase-a/                浏览器版（Go，Subsystem=2，控制台程序）
│   ├── phase-edgeapp/          桌面版（Go，-H windowsgui，Edge/Chrome 承载）
│   ├── 原型源码/               早期 Go / Rust 原型
│   ├── 跨平台编译/             跨平台构建实验
│   ├── 脚本/                   辅助脚本目录
│   └── 脚本-*.py               图标生成、双包验收、UI 端到端验收、macOS 打包
├── docs/                       产品页 + 设计与评估报告
└── releases/                   发布的 zip 包
```

> `src/脚本-*.py` 中的路径一律**基于脚本自身位置解析**（`os.path.dirname(os.path.abspath(__file__))`），
> 不含硬编码绝对路径——这样整个目录搬到任何位置都能直接跑。
