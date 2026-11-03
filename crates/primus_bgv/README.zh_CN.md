# primus_bgv

[English](README.md) | 简体中文

固定 u64、rank-one 的 BGV 系数及可选槽工作流。原生密文存储 `[c0,c1]`，phase 为
`c0+c1*s = lift(m)+p*e`。首版要求每个 q_i≡1 mod p，支持私钥/公钥加密、线性
运算及未缩放的 plaintext add/mul；ct×ct、relin、密文旋转与降模在后续实现。

## 使用流程

1. 用 `BgvParameters::try_coefficients(N,p,&moduli,secret_law,sigma)` 构造参数，
   或用 `try_with_error_distribution` 显式选择现有 Gaussian/CBD 误差分布。
2. 将参数消费进一个 `BgvContext`。`BgvClient::generate` 生成完整 N 维秘密并拥有
   可复用、drop 时擦除的恢复 scratch；高级调用者可用 `try_from_secret_key`
   移交已有变换域秘密。
3. 用 `context.new_ciphertext()` 准备输出。直接用 client 私钥加密，或生成
   `client.public_key(rng)` 并绑定 `context.public_key_encryptor(&key)` 做公钥加密。
4. 准备一次 `BgvEvaluator::new(&context)`，调用 add/sub/neg 和 add_plain/mul_plain
   的 `_to`/`_assign`，显式选择 unsigned/centered `PlaintextEmbedding`。两个原生
   组件都参与乘法；明文 lift 不乘 BFV Delta 或额外的 p。
5. 用 `client.decrypt_to(input,&mut output)` 恢复 canonical 系数；便利方法
   `decrypt` 额外分配返回多项式。

[coefficients 示例](examples/coefficients.rs) 包含完整公钥加密、明文求值及精确恢复。
明文和输出长度在采样或写入前检查；密文 canonical residues、实际秘密、有序 basis
和 NTT 身份仍由调用者保证。

## 精确恢复与噪声

每个误差系数只采样一次，编码到所有 RNS limbs，再乘 p。Gaussian/CBD 使用后端
真实分布，公钥 ephemeral r 独立采用 CBD1。公钥 phase 是 p*e_pk；新公钥密文完整
误差为 `p*(e_pk*r+e0+e1*s)`，乘法发生在完整 negacyclic 环。

解密计算 phase、逆 NTT，精确 CRT 重构 x∈[0,Q)。下半区返回 x mod p，上半区
返回 (x-Q) mod p；即使 Q mod p=1，也不能省略后者的 correction。总 Q 可以超过
128 位，复用已有多 limb 算术，不借用 BFV decoder、浮点近似或 BigInt normal 依赖。

预期整数 phase 必须处于 (-Q/2,Q/2)；跨越 Q 的约简可能改变模 p 的消息。参数构造
用 `p*maximum_error+(p-1) <= floor(Q/2)` 检查 fresh-private 充分界，覆盖两种
embedding。公钥/求值电路还须计算 PK error、full-ring 卷积、明文 carry 和全部
操作的贡献；私钥准入不证明这些电路或安全性。密文模数必须是适配当前 u64 NTT 的
素数（q_i<2^62）；rootability 检查不等于素性认证。

## 槽与子环

启用 `batching` 后使用 BFV 同样消费的共享 `primus_encoding::BatchingEncoder`。
素数 p≡1 mod 2n 提供 n 个槽，布局为 ±5^j 两行。编码器拥有 small-n 明文 NTT，
其旋转映射不执行密文旋转或生成 evaluation keys。

编码 slots 前缀（未用槽补零）后，`embed_to` 将 f(Y) 映射成 f(X^(N/n))，完整
输出的 off-stride 系数为零。只有明文使用较小子环，实际秘密、误差、NTT 和密文
保持 N。完整 N 维解密后，`extract_to` 验证子环支撑，再由 `decode_to` 用预分配
scratch 恢复 slots。p 只需支持明文 n，而 q_i 必须支持 fullN。
[slots 示例](examples/slots.rs) 使用 n32/N128/p193，p 无法构造 fullN 明文 NTT。

## 资源与命令

Context 拥有一份有序 basis、采样预计算及 fullN 变换表，client/evaluator/public
加密器借用它。Prepared 系数加密、精确恢复及求值不新增分配；秘密、ephemeral 和
恢复存储在 drop 时擦除。密文/views 只承载实际存储，不新增 Domain 或系数类型泛型。

默认 features 为空；`batching` 启用共享槽编码，`simd` 转发已有 nightly SIMD 后端。

```sh
cargo run -p primus_bgv --example coefficients
cargo run -p primus_bgv --example slots --features batching
cargo test -p primus_bgv --features batching --lib --tests
cargo clippy -p primus_bgv --all-targets --features batching -- -D warnings
cargo bench -p primus_bgv --bench workflow --features batching
```

测试采用独立 DFT、schoolbook phase 和整数 oracle，覆盖偶数 p 的 centered half
与 150 bit Q。基准测量包含真实采样、encode/embed、公钥加密、明文求值、精确恢复和
槽提取/解码的完整请求，资源准备不计时。参数和固定 seed 是功能样例，不是安全预设。
