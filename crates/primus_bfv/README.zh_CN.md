# primus_bfv

[English](README.md) | 简体中文

采用原生物理组件 `[c0,c1]`、phase `c0+c1*s` 的 BFV 系数加密与恢复。
Rank-one 后端使用 `u64` 残数、`BarrettModulus<u64>` 和 `U64DcrtTable`；总模数
Q 可以超过64位。与 `primus_glwe_rns` 共享数值秘密存储时，不改变实际系数秘密。

本 crate 负责 BFV 参数、密文/公钥语义、私钥/公钥消息加密和明文恢复。
尚未提供完整 leveled evaluator、密文乘法/重线性化、slots 或模数链操作。
唯一系数 codec 保留在 `primus_encoding`；RNS 算术、NTT、sampler 和秘密存储复用
底层实现。

## 系数工作流

运行完整[示例](examples/coefficients.rs)：

```sh
cargo run -p primus_bfv --example coefficients
```

1. 用 `BfvParameters::try_new(N, t, gamma, &Q, secret_law, sigma)` 构造参数；
   显式 Gaussian/CBD 分布使用 `try_with_error_distribution`。
2. 根据 `poly_length()` 和 `base_q().moduli()` 准备一个 `U64DcrtTable`。
   用 `encryption_parameters().secret_key_sampler()` 生成系数秘密，再用
   `DcrtGlweSecretKey::from_coeff_secret_key` 转换。
3. 绑定 `BfvSecretKeyContext::try_new(&key, &parameters, &table)`。需要时用
   `BfvPublicKey::new(&client, rng)` 生成原生公钥，再构造
   `BfvPublicKeyEncryptor::try_new(&public, &parameters, &table)`。
4. 一次性分配 `BfvCiphertext`、明文输出和
   `BfvDecryptWorkspace::new(&parameters)`，通过 `encrypt_to`、
   `encrypt_centered_to`、`decrypt_to` 复用。

两种系数入口都接受恰好 N 个 `[0,t)` 中的规范值。Unsigned 将 m 提升为 m；
centered 使用 `[-floor(t/2), ceil(t/2))`。解密返回 `[0,t)` 中的规范值。
这些是多项式系数，不是 SIMD slots。

## 缩放与表示

加密满足 `c0+c1*s = delta*lift(m)+e (mod Q)`，其中 `delta=floor(Q/t)`。
私钥加密直接计算 `c0=delta*lift(m)+e-c1*s`，在 c0 唯一一次 NTT 前将编码
融合进系数噪声。原生公钥加密计算 `c0=pk0*u+e0+delta*lift(m)`、
`c1=pk1*u+e1`，复用一个 ephemeral 多项式，每个含噪组件只变换一次。
普通操作不将整份密文转回 raw GLWE。

`encrypt_plaintext_lift_crt_to` 接受**未缩放**的规范 CRT lifts，采用系数域、
modulus-major Q 顺序，恰好乘一次 delta。`encrypt_encoded_crt_to` 接受
**已经缩放**的规范 phase（包括 codec 输出），不再乘 delta。将已编码输出传入
lift 入口会重复缩放。方法名明确区分两种语义，不增加中间多项式。

`phase_to` 输出一个 **DCRT** 多项式，不执行 INTT 或解码。`decrypt_to` 计算
phase、执行 INTT，再调用唯一 BFV codec。`size()` 维护存储几何；`base_q()`
维护 basis 算术；`codec()` 维护缩放/恢复常量；`encryption_parameters()` 维护
预备 sampler。BFV 不再逐项转发底层访问器。

Raw GLWE 保留 `[a,b]` 与 `b-a*s`。`write_raw_glwe_to` 显式写出
`[a=-c1,b=c0]`；`set_from_raw_glwe` 导入 `[c0=b,c1=-a]`。边界转换复制并取负
规范残数，不分配、不执行 NTT。[Hybrid-RNS 示例](examples/hybrid_rns_key_switch.rs)
及 raw 对照基准使用这些桥接，因为现有 switching/GGSW 密钥保持 raw 语义。
`gadget_parameters` 为这些 raw 消费者准备分解权重，不携带加密 sampler，也不是
原生 BFV evaluator。

组件、tensor、求值密钥和 opening 的符号推导见
[RNS phase 约定](../../guides/development/rns-phase-conventions.md)（English）。

## 资源与验证

Prepared `*_to` 调用不分配临时存储。公钥 `encrypt_plaintext_lift_crt` 和私钥
`decrypt` 便利方法只分配返回结果。公钥 encryptor 拥有一个 ephemeral workspace，
需要可变访问；并发使用不同 encryptor，共享密钥、参数和 table。解密复用一个
phase buffer 和恰好 `codec().decode_scratch_len(N)` 个转换元素，单 Q prime 的
转换 buffer 长度为零。

Ephemeral/解密 scratch 在 drop 时擦除。显式 `workspace_mut().zeroize()` 或
`Zeroize::zeroize(&mut decrypt_workspace)` 擦除内容并保留 allocation/geometry。
调用会覆盖 scratch，不在每次操作后额外扫描擦除。

参数构造验证 sampling/basis 配对，并用误差分布的完整支撑验证 fresh 私钥恢复
充分条件。它不证明公钥/求值后的恢复条件或安全级别。实际秘密和 NTT
root/evaluation identity 由调用方保证。操作绑定只检查一次 geometry 和数值模数
顺序，不再引入独立公开 Domain 类型。优化 u64 NTT 后端要求 Q prime 小于 `2^62`
且与 N 兼容。

完整长度错误在采样/写入前拒绝。Codec 在采样噪声后、c0 NTT 前检查系数范围；
codec/RNG/NTT panic 可能留下部分输出或 scratch。精确契约以方法 rustdoc 为准。

## Features 与检查

默认 features 为空。`simd` 转发到共享算术/codec 后端，遵循其 nightly SIMD 要求。

```sh
cargo check -p primus_bfv --all-targets
cargo test -p primus_bfv --lib --tests
cargo run -p primus_bfv --example coefficients
cargo run -p primus_bfv --example hybrid_rns_key_switch
cargo clippy -p primus_bfv --all-targets -- -D warnings
cargo bench -p primus_bfv --bench public_encryption
cargo bench -p primus_bfv --bench key_switching
```

测试使用小规模功能参数。Direct-DFT/u128 oracle 根据真实系数秘密检查原生组件
符号、共同 RNS 残差、公钥 phase、embedding 和精确恢复；还覆盖显式 raw 桥接、
错误重复缩放负例、完整长度/basis 检查、错误来源、workspace 复用/擦除及独立分配
契约。Criterion 测量明确工作流；raw 对照计时不包含 setup 中的桥接。
