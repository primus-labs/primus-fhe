# primus_bfv

[English](README.md) | 简体中文

基于 rank-one、`u64` RNS GLWE 的 BFV 系数加密与恢复。每个密文 prime 占一个
`u64`，总模数 Q 可以超过 64 位。默认后端为 `BarrettModulus<u64>` 和
`U64DcrtTable`。

当前 crate 负责 BFV 参数、私钥/公钥消息加密、明文恢复和 gadget 参数构造。
尚未提供完整 leveled BFV evaluator、密文乘法/重线性化、slots 或模数链操作。
唯一的系数 codec 保留在 `primus_encoding`；存储、密钥和 raw 求值原语复用
`primus_glwe_rns` 与 `primus_lattice`。

## 系数工作流

运行完整[示例](examples/coefficients.rs)：

```sh
cargo run -p primus_bfv --example coefficients
```

1. 使用 `BfvParameters::try_new(N, t, gamma, &Q, secret_law, sigma)` 构造参数；
   显式 Gaussian/CBD 误差分布使用 `try_with_error_distribution`。
2. 根据参数的多项式长度和有序 Q contexts 准备一个 `U64DcrtTable`。使用
   `secret_key_sampler()` 生成系数秘密，再通过
   `DcrtGlweSecretKey::from_coeff_secret_key` 转换。
3. 使用 `BfvSecretKeyContext::try_new(&key, &parameters, &table)` 绑定私钥。
   需要公钥加密时，由 `encryption_parameters()` 和 `base_q()` 生成 raw 公钥，
   再准备 `BfvPublicKeyEncryptor`。
4. 一次性分配密文/明文输出和 `BfvDecryptWorkspace::new(&parameters)`，通过
   `encrypt_to`、`encrypt_centered_to`、`decrypt_to` 反复复用。

两种系数加密入口都接受恰好 N 个 `[0,t)` 中的规范值。Unsigned 将 m 提升为 m；
centered 使用 `[-floor(t/2), ceil(t/2))`。解密始终返回 `[0,t)` 中的规范值。
这些入口编码多项式系数，不是 SIMD slots。

## 缩放与表示

加密 phase 为 `b-a*s = delta*lift(m)+e (mod Q)`，其中 `delta=floor(Q/t)`。
BFV 编码在 body 唯一一次正向 NTT 前融合进系数噪声。公钥加密复用一个 ephemeral
多项式，每个含噪密文 component 只变换一次。

`encrypt_plaintext_crt_to` 接受**未缩放**的规范 CRT 明文 lifts，使用系数域、
modulus-major Q 顺序，并且只乘一次 delta。将已经经过
`BfvRnsCodec::encode_coeffs_to` 缩放的输出传入会重复缩放。调用方直接提供已编码
phase 时，应使用 `primus_glwe_rns` 的 codec-free raw 加密接口。

`phase_to` 输出一个 **DCRT** 多项式，不执行逆变换或解码。`decrypt_to` 计算
phase、执行 INTT，再调用唯一的 BFV 系数 codec。`gadget_parameters(log_basis,
levels)` 构造共享不可变 sampler/base tables 的普通 codec-free gadget 参数；
gadget 权重不等于 BFV 消息缩放。

## 资源与验证

Prepared `*_to` 调用不分配临时存储。公钥 `encrypt_plaintext_crt` 和私钥
`decrypt` 便利方法只分配返回的结果。公钥 encryptor 拥有 ephemeral workspace，
需要可变访问；并发调用使用不同 encryptor，共享密钥、参数和 table。解密复用
一个 phase buffer 和恰好 `codec.decode_scratch_len(N)` 个转换元素；单个 Q
模数的转换 buffer 长度为零。

公钥 ephemeral 和解密 scratch 在 drop 时擦除。显式调用
`workspace_mut().zeroize()` 或 `Zeroize::zeroize(&mut decrypt_workspace)`
会擦除内容，同时保留 allocation/geometry 以便复用。每次调用覆盖 scratch，
不在每次操作后额外执行一次完整擦除扫描。

参数构造验证有序 basis/sampler 配对，并用误差 sampler 的完整最大幅度验证
fresh 私钥恢复的充分条件。Unsigned bound 同时覆盖 centered lifting。它不证明
公钥/求值后的完整 phase noise 可恢复，也不证明 NTT identity 或安全级别。
绑定检查 geometry 和数值模数顺序；实际秘密和 NTT root/evaluation identity 仍由
调用方保证。优化的 `u64` NTT 后端要求密文 prime 小于 `2^62` 且与 N 兼容。

完整 layout 错误在写入/随机采样前拒绝。系数是否位于规范范围由 codec 在噪声
采样后、body NTT 前检查；codec、RNG、callback 或变换 panic 可能留下部分输出和
scratch。具体未检查的数学条件以各方法 rustdoc 为准。

## Features 与检查

默认 features 为空。`simd` 转发到共享 GLWE/codec 后端，遵循其 nightly SIMD
要求；该 feature 不选择另一种方案。

```sh
cargo check -p primus_bfv --all-targets
cargo test -p primus_bfv --lib --tests
cargo run -p primus_bfv --example coefficients
cargo clippy -p primus_bfv --all-targets -- -D warnings
cargo bench -p primus_bfv --bench public_encryption
cargo bench -p primus_bfv --bench key_switching
```

测试覆盖系数 embedding、与独立 CRT 编码对照的 delta 恰好一次、direct-DFT/u128
恢复 oracle、明文乘法、有序 domain/完整 layout 拒绝、错误来源、sampler 共享、
workspace 擦除/复用和独立分配契约。测试使用小规模功能参数，性能计时通过独立
benchmark 运行完成。
