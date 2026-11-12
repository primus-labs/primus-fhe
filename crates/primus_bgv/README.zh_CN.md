# primus_bgv

[English](README.md) | 简体中文

在 rank-one、`u64` RNS 上执行 leveled BGV。原生密文存储 `[c0,c1]`，phase
为 `c0+c1*s`，误差是 p 的倍数，消息带可逆校正因子。每个密文素数与明文模数 p 互素。

## 从系数或槽开始

```sh
cargo run -p primus_bgv --example coefficients
cargo run -p primus_bgv --example slots --features batching
```

[系数示例](examples/coefficients.rs) 用公钥加密多项式，执行明文常数加法和缩放，
然后恢复结果。[槽示例](examples/slots.rs) 对打包值逐槽执行同一运算。

1. 创建 `BgvParameters` 并移入 `BgvContext`。
2. 生成 `BgvClient` 和公钥，用 `context.public_key_encryptor` 将公钥绑定到加密器。
3. 用 `context.new_ciphertext(level)` 分配输出，复用 `BgvEvaluator` 做明文运算，
   再用 `client.decrypt` 或 `client.decrypt_to` 恢复结果。

加密接受 N 个位于 `[0,p)` 的规范系数。整环打包使用 `context.batching_encoder()`，
要求明文素数 p ≡ 1 (mod 2N)。将槽编码到明文多项式，解密后再解码。示例参数用于功能演示。

## 进阶工作流

| 示例 | 用途 |
| --- | --- |
| [ciphertext_multiplication](examples/ciphertext_multiplication.rs) | 复用重线性化密钥和准备好的乘法器。追加 `-- --hybrid` 选择分区 QP 密钥。 |
| [leveled_coefficients](examples/leveled_coefficients.rs) | 先核对声明电路的预算，再求值、换秘密并在两次 drop 后恢复。支持 `-- --hybrid`。 |
| [leveled_slots](examples/leveled_slots.rs) | 对加密子环槽相乘，降模一次后执行行旋转和行交换。需要 `batching`。 |
| [collective](examples/collective.rs) | 合并公钥贡献，执行两轮重线性化建钥。 |
| [public_worker](examples/public_worker.rs) | 导出公开材料，在独立 worker context 中求值。 |

```sh
cargo run -p primus_bgv --example leveled_coefficients -- --hybrid
cargo run -p primus_bgv --example leveled_slots --features batching
cargo run -p primus_bgv --example public_worker
```

`evaluation` 提供 prepared operation，`keys` 提供密钥配置，`collective` 提供共享密钥贡献。
[Native Hybrid 与 collective 建钥](../../guides/development/native-hybrid-keys.md)

## 生成参数与声明电路的准入

`planning::BgvParameterRequest` 按明确指定的资源和采样律生成 NTT 素数。
`BgvCircuitPlan` 检查声明的普通电路的算术预算，并提供各 level 通过准入的密钥配置。
`security_inputs()` 为单独的安全分析导出实际数值域，选择 Hybrid 时包含 QP。
计划的安全分析状态为 `NotEvaluated`。Collective 和 raw 协议需要自己的预算。
[电路预算](../../guides/development/bgv-evaluation.md#public-static-circuit-budgets) ·
[参数与安全参考](../../guides/development/ordinary-parameter-budgets.md)

## Level、槽与数值契约

Level zero 使用完整 Q，每个后续 level 去掉末尾素数。按实际 level 生成角色密钥。
恢复使用密文携带的 level 和校正因子。同一 level 的不同密文可以有不同因子。
向求值器传递完整密文，使因子与余数一起更新。每次恢复时，预期整数 phase 必须位于
当前模数的中心区间。 [BGV 求值](../../guides/development/bgv-evaluation.md) ·
[RNS phase 约定](../../guides/development/rns-phase-conventions.md)

系数 p 可以是合数。槽编码要求明文素数 p ≡ 1 (mod 2n)，其中 n 为所选明文环长度。
子环通过 `embed_to` 和 `extract_to` 在子环明文和完整环之间转换。
正向旋转在各行内左移，行交换对调两行。 [打包编码器](../primus_encoding/README.zh_CN.md)

准备好的算子借用 context 和密钥，持有可变 scratch。并发请求各用一套算子。
显式 raw 互操作要求实际基、变换、秘密和校正因子。
[Context 绑定与 raw 导入](../../guides/development/scheme-context-binding.md)

## Collective 与开封

Collective 示例演示本地建钥算术。应用负责认证、参与者与轮次绑定、一次性状态，
以及发布部分 phase 前的隐私 flooding。校正因子和密文余数一同认证。
[Collective 与开封契约](../../guides/development/scheme-context-binding.md#collective-与安全-opening-的分工)

## Features 与基准

默认 features 为空。`batching` 启用槽编码，`parallel` 启用 DCRT limb 调度，
`simd` 转发 nightly SIMD 支持。见 [feature 与验证指南](../../guides/development/testing.md)。

```sh
cargo bench -p primus_bgv --bench leveled --features batching
```

计时终点与历史负载范围见[性能指南](../../guides/performance/README.zh_CN.md#bfv-and-bgv)。

## 公共对象持久化

用 `to_public_bytes` / `from_public_bytes` 保存和恢复公开 context，
用 context 的 `export_*` / `import_*` 处理密文和角色密钥。密文保存校正因子。
为接收方设置 `PublicObjectLimits`，将字节和应用角色、身份一起认证。秘密由客户端保留。
[公共对象持久化契约](../../guides/development/public-storage.md) ·
[公开 worker 示例](examples/public_worker.rs)
