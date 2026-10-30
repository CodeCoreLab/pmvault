# 双 Module 副本关系与同步约定

> 状态：**当前为「逐字节相同的副本」关系**，未来计划抽公共 module。
> 本文档记录现状、风险与强制同步约定，供后续维护者与代码评审使用。

---

## 1. 现状：两个 Go module 共享同一份 `internal/vault`

本仓有两个 Go module：

| 路径 | module 名 | 产品形态 | 入口 |
|---|---|---|---|
| `src/phase-a/` | `vaultd` | 服务端（HTTP 服务 + 内嵌前端） | `cmd/vaultd/main.go` |
| `src/phase-edgeapp/` | `vaultgui` | 桌面版（Edge `--app` 模式承载同一套前端） | `cmd/vaultgui/main.go` |

两者的 `internal/vault/` 与 `internal/vault/web/` **逐字节相同**（`version.go` 除外，
它只有一行 ldflags 注释里的 module 名不同）：

```
src/phase-a/internal/vault/{app,crypto,errors,extra,store,version}.go
src/phase-a/internal/vault/web/{app.js,index.html,app.css}
src/phase-edgeapp/internal/vault/{app,crypto,errors,extra,store,version}.go
src/phase-edgeapp/internal/vault/web/{app.js,index.html,app.css}
```

**差异只在 `cmd/` 入口**：`vaultd` 是纯服务端进程，`vaultgui` 额外负责
定位浏览器内核、创建独立 `--user-data-dir`、以 `--app` 模式拉起窗口、单实例互斥。

这意味着：

- `phase-a` 仓**不含** `phase-edgeapp` 的任何独有业务代码；
- 任何对 `internal/vault` 的修改，**必须**同时落到两份，否则两个产品的行为会分叉；
- 分叉的后果不是编译错误，而是**同一个密码管理器在「服务端版」和「桌面版」上
  安全行为不一致** —— 例如只有桌面版补了审计日志，或只有服务端版修了填充校验。

---

## 2. 强制同步约定

### 2.1 改一处，必须改另一处

对 `internal/vault/` 下任何文件的修改，都必须在**同一次提交**内同步到
`src/phase-edgeapp/internal/vault/` 的同名文件。推荐做法：

```bash
# 从 phase-a 复制到 phase-edgeapp（version.go 除外，它有独立的 module 名注释）
cd src
for f in app crypto errors extra store vault_test; do
  cp "phase-a/internal/vault/$f.go" "phase-edgeapp/internal/vault/$f.go"
done
for f in app.js index.html app.css; do
  cp "phase-a/internal/vault/web/$f" "phase-edgeapp/internal/vault/web/$f"
done
```

**注意**：`version.go` 不要复制 —— 两份的 ldflags 注释分别写 `vaultd/...` 与
`vaultgui/...`，是有意不同的。

### 2.2 提交前必须做逐文件一致性校验

```bash
cd src
for f in app crypto errors extra store vault_test; do
  diff -q "phase-a/internal/vault/$f.go" "phase-edgeapp/internal/vault/$f.go" \
    && echo "$f.go IDENTICAL" || echo "$f.go *** DIFFERS ***"
done
for f in app.js index.html app.css; do
  diff -q "phase-a/internal/vault/web/$f" "phase-edgeapp/internal/vault/web/$f" \
    && echo "web/$f IDENTICAL" || echo "web/$f *** DIFFERS ***"
done
# version.go 单独看：只应有一行 ldflags 注释不同
diff "phase-a/internal/vault/version.go" "phase-edgeapp/internal/vault/version.go"
```

### 2.3 两个 module 都要构建 + 测试通过

```bash
( cd phase-a       && go build ./... && go test ./... )
( cd phase-edgeapp && go build ./... && go test ./... )
```

只测一个 module 不算数 —— 因为两份代码在物理上是两份，编译器不会告诉你另一份坏了。

---

## 3. 为什么暂时保留副本关系（而不是立刻抽公共 module）

抽公共 module（例如 `src/core`，两个 module 用 `replace` 指向）看起来更优雅，
但当前不做，原因是它会牵动构建与发布流程，风险收益比不合适：

1. **构建脚本耦合**：仓内的跨平台编译脚本（`src/跨平台编译/xbuild_*.py`）
   与打包脚本（`src/脚本-验收双包.py`）目前都按「两个独立 module 分别编译」组织，
   引入第三个 module 后需要重新处理 `replace` 指令、依赖下载与离线打包
   （仓内已有 `xbuild_offline.py` 专门处理离线依赖场景）。
2. **发布流程耦合**：两个产品（`vaultd` / `vaultgui`）是**分别发布**的，
   各自有独立的二进制与安装包。公共 module 的版本一旦被两个 module 同时依赖，
   就需要引入「公共 module 的版本策略」，否则会出现
   「A 产品用了新公共库、B 产品还钉在旧版」的状态。
3. **改动面**：这是架构级变更，需要单独评审、单独排期，
   不应该和一堆安全修复混在一次改动里。

**计划中的升级路径**（另立任务决策，不在本次修复范围内）：

1. 先在公共 module 里放**纯逻辑、无平台依赖**的部分
   （`crypto.go` / `errors.go` / `schema` 之类），
   平台相关部分（`cmd/` 入口、浏览器拉起、单实例互斥）继续留在各自 module；
2. 公共 module 用**独立版本号**（比如 `src/core/go.mod` 里的 `module github.com/.../core`），
   两个产品 module 通过 `replace` 或 `require` 引用；
3. 在抽公共 module 之前，**先把副本关系消掉**：
   本次修复已经建立「逐文件 diff 校验」的机制（见 2.2），
   可以在 CI 里加一步「两份必须一致」的检查，把约定从人工变成机器强制。

---

## 4. 本次修复涉及的文件（2026-10-30）

本次安全修复同时改动了以下文件，**两份 module 均已同步并通过 `diff -q` 校验**：

| 文件 | 改动内容 |
|---|---|
| `internal/vault/crypto.go` | P1-1 KDF 参数解析失败改为明确报错；P1-2 PKCS#7 填充严格校验 + 空密文前置检查；P2-5 密码强度策略 |
| `internal/vault/app.go` | P1-3 `reveal_entry` / `unlock` 补审计；P2-6 会话 GC 后台协程；P2-5 门槛调用点收敛到 `MeetsStrengthPolicy` |
| `internal/vault/store.go` | P1-4 审计日志保留策略 `PruneLogs`；P2-4 备份目录 ACL 收紧 |
| `internal/vault/vault_test.go` | 上述四项对应的单元测试 |

未改动：`errors.go`、`extra.go`、`version.go`、`web/` 下的前端文件。
