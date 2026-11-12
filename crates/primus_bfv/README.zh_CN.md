# primus_bfv

[English](README.md) | 简体中文

在 rank-one、`u64` RNS 上执行 BFV 系数和槽运算。原生密文存储 `[c0,c1]`，
phase 为 `c0+c1*s`，消息尺度为 `floor(Q/t)`。每个余数占一个字，完整模数 Q
可以跨多个字。

## 系数与 slots

```sh
cargo run -p primus_bfv --example coefficients
cargo run -p primus_bfv --example slots --features batching
```

[系数示例](examples/coefficients.rs) 用公钥加密多项式，执行明文常数加法和缩放，
然后恢复结果。[槽示例](examples/slots.rs) 对打包值逐槽执行同一运算。

1. 创建 `BfvParameters` 并移入 `BfvContext`。
2. 生成 `BfvClient` 和公钥，用 `context.public_key_encryptor` 将公钥绑定到加密器。
3. 用 `context.new_ciphertext(level)` 分配输出，复用 `BfvEvaluator` 做明文运算，
   再用 `client.decrypt` 或 `client.decrypt_to` 恢复结果。

加密接受 N 个位于 `[0,t)` 的规范系数。整环打包使用 `context.batching_encoder()`，
要求明文素数 t ≡ 1 (mod 2N)。将槽编码到明文多项式，解密后再解码。示例参数用于功能演示。

## 选择进阶工作流

| 示例 | 用途 |
| --- | --- |
| [ciphertext_multiplication](examples/ciphertext_multiplication.rs) | 复用重线性化密钥和准备好的乘法器。追加 `-- --hybrid` 选择分区 QP 密钥。 |
| [leveled_coefficients](examples/leveled_coefficients.rs) | 乘法、平方、换秘密，并在两次 prime drop 后解密。 |
| [subring_slots](examples/subring_slots.rs) | 打包较小明文环，保留完整环密文，在降模后恢复。需要 `batching`。 |
| [working_basis](examples/working_basis.rs) | 验证并执行保持外部 level zero 的临时工作基平方链。追加 `-- --radix` 选择 radix 密钥。 |
| [explicit_coefficients](examples/explicit_coefficients.rs) | 借用已有秘密并复用显式恢复工作区。 |
| [hybrid_rns_key_switch](examples/hybrid_rns_key_switch.rs) | 转换 phase 约定以使用 raw RNS GLWE 换钥和 GGSW 运算。 |

```sh
cargo run -p primus_bfv --example ciphertext_multiplication -- --hybrid
cargo run -p primus_bfv --example subring_slots --features batching
cargo run --release -p primus_bfv --example working_basis
```

`evaluation` 提供 prepared operation，`keys` 提供密钥配置，`planning` 提供普通算术预算。
按实际密文 level 生成角色密钥。打包自同构用法见[打包编码器](../primus_encoding/README.zh_CN.md)
和 [BGV 行操作示例](../primus_bgv/examples/leveled_slots.rs)。

## 数值与所有权契约

Level zero 使用完整 Q。每一级从前一级去掉末尾素数，按最近整数舍入。
Context 分配的密文携带该 context 和 level。准备好的算子借用 context 和密钥，
持有可变 scratch。并发请求各用一套算子。
[Context 绑定与 raw 导入](../../guides/development/scheme-context-binding.md)

Q 由互异的 NTT 素数组成。默认系数构造器选择 decoder gamma = 2⁶¹−1，要求 t < gamma。
参数构造检查新鲜私钥密文的恢复条件，公钥和求值结果需要各自的完整 phase 界。
`BfvMultiplication` 默认使用 Exact，也支持 HPSPOVERQ。乘法后端和 Radix/Hybrid
密钥后端可以独立选择。 [求值与恢复界](../../guides/development/bfv-evaluation.md) ·
[工作基与算术准入](../../guides/development/bfv-working-basis.md) ·
[参数与安全参考](../../guides/development/ordinary-parameter-budgets.md)

Collective 建钥、fresh lookup 和 raw 开封各有独立的角色与噪声要求。Raw GLWE 和
原生 BFV 的 mask 符号约定不同，跨边界时使用显式 phase 转换。
[Native Hybrid 与 collective 密钥](../../guides/development/native-hybrid-keys.md) ·
[RNS phase 约定](../../guides/development/rns-phase-conventions.md)

## Features 与基准

默认 features 为空。`batching` 启用槽编码，`parallel` 启用 DCRT limb 调度，
`simd` 转发 nightly SIMD 支持。见 [feature 与验证指南](../../guides/development/testing.md)。

```sh
cargo bench -p primus_bfv --bench multiplication --features batching
```

计时终点与历史负载范围见[性能指南](../../guides/performance/README.zh_CN.md#bfv-and-bgv)。

## 公共对象持久化

用 `to_public_bytes` / `from_public_bytes` 保存和恢复公开 context，
用 context 的 `export_*` / `import_*` 处理密文和角色密钥。为接收方设置
`PublicObjectLimits`，将字节和应用角色、身份一起认证。秘密由客户端保留。
[公共对象持久化契约](../../guides/development/public-storage.md) ·
[公开 worker 示例](../primus_bgv/examples/public_worker.rs)
