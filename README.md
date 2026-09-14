# escrow

DOFS 应用的密钥托管（key custody）层：`ServerMaster` 托管模式的前后端实现，供多个 DOFS 应用共享。

## 定位与 custody 轴

DOFS 只定义一种格式：对象体是按 64 KiB 分块的 AES-256-GCM 密文，用每对象一把 32 字节 DEK 加密；DEK 只以被包裹的信封形态存在。**custody 轴回答一个问题：谁有能力拆开 DEK 信封。**

escrow 把这个选择做成显式的一等概念，避免应用不知不觉滑进某种托管模型：

| profile | 状态 | 含义 |
| --- | --- | --- |
| `ServerMaster` | **已实现**（本仓库） | 部署持一把 32 字节 master key：subject key（用户 KEK / namespace KEK）由 master 生成并包裹持久化，DEK 由 subject key 包裹。服务端随时可解任何文件。即"静态加密、服务端托管"。 |
| `ClientHeld` | **保留，未实现** | 真 E2E：DEK 信封只由客户端创建与拆开，服务端只存打不开的 opaque 字节。它将来会作为独立实现落地，**不允许**从 `ServerMaster` 隐性长出来。 |

密码学原语全部委托 `github.com/willvar/dofs`（`WrapKey`/`UnwrapKey`/`GenerateKey`/`Clear`）——escrow 提供词汇与所有权纪律，不发明新密码学。

## Go 端

```go
import "github.com/willvar/escrow"

// 从部署 secret 建 master key（与 domus 现有语义一致：hex 解码取前 32 字节）
custody, err := escrow.NewServerMasterFromSecret(cfg.Server.EncryptionSecret)
defer custody.Close()

// 生成并持久化 subject key（用户 KEK / namespace KEK）
subjectKey, err := custody.GenerateSubjectKey()
defer escrow.Zero(subjectKey)
wrappedSubject, err := custody.WrapSubjectKey(subjectKey)

// DEK 层：不需要 master key
wrappedDEK, err := escrow.WrapDEK(subjectKey, dek)
dek, err := escrow.UnwrapDEK(subjectKey, wrappedDEK)
defer escrow.Zero(dek)
```

对象体加密/解密（DOFS v1 wire format）直接用 `dofs.EncryptStream` / `dofs.DecryptStream` / `dofs.DecryptRange`；escrow 不重复提供。

## 浏览器端（vue/）

`@willvar/escrow-vue` 提供浏览器侧的同一套能力：DEK 生成与 hex 编解码、`zeroize`，以及 DOFS v1 对象编解码（`encryptBlob` / `decryptBlob`，AAD 为 8 字节 BE chunk 序号）。不依赖 Vue，命名沿用 notix 的仓库布局约定。

```ts
import { generateDEK, keyToHex, encryptBlob, decryptBlob, zeroize } from '@willvar/escrow-vue'

const dek = generateDEK()
const blob = await encryptBlob(dek, fileBytes) // 浏览器端加密后直传 OSS
// …经服务端校验授权后取回 dek（ServerMaster 模式下服务端可解包）
const plain = await decryptBlob(dek, blob)
zeroize(dek)
```

## 前后端字节兼容

Go 测试与前端测试共用同一份 golden fixture：仓库根 `testdata/golden.json`。它包含 DOFS v1 对象密文向量与 DEK 包裹向量，两侧实现都对其断言解密结果一致，防止漂移。fixture 由 `go run ./scripts/golden` 重新生成（生成方向含随机 nonce，因此向量重生成后内容会变，但始终有效）。

## 兼容性承诺

`ServerMaster` 与现有 DOFS 应用已落盘数据的密钥层级完全同构：`master key ← hex secret`、`KEK 信封`、`DEK 信封`、`DOFS v1 对象格式` 均未改变。应用迁移到 escrow 必须是纯代码替换，不允许改变已落盘数据的任何格式；验收标准是切换后能用原数据原配置原样解出全部文件。

## 开发

```sh
make check     # 全部检查（Go + 前端）
make golden    # 重新生成 testdata/golden.json
```
