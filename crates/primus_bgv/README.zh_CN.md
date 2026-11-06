# primus_bgv

[English](README.md) | 简体中文

固定 u64、rank-one 的 leveled BGV，支持 `q_i ≡ 1 (mod p)` 参数族。原生密文为
`[c0,c1]`，phase 是 `c0+c1*s=lift(m)+p*e`。提供私钥/公钥加密、线性/明文求值、
乘法、重线性化、换钥、自同构、prime drop 和可选槽工作流。

## 从系数或槽开始

[系数示例](examples/coefficients.rs) 两次计算 `(message+1)*scalar`；
[槽示例](examples/slots.rs) 在 `n=N` 下逐槽执行相同运算。
它们复用 context、公钥、evaluator 和输出；密文乘法与求值密钥配置单独介绍。

```sh
cargo run -p primus_bgv --example coefficients
cargo run -p primus_bgv --example slots --features batching
```

1. 用 `BgvParameters::try_coefficients(N,p,&Q,secret_law,sigma)` 构造参数，随后消费进
   `BgvContext::try_new(parameters)`。显式 Gaussian/CBD 分布用
   `try_with_error_distribution` 选择。
2. 生成 `BgvClient::generate(&context,rng)`，保留 `client.public_key(rng)`，
   通过 `context.public_key_encryptor(&key)` 绑定公钥。
3. 准备 `BgvEvaluator::new(&context,0)`、`context.new_plaintext()` 和
   `context.new_ciphertext(0)`。公钥加密使用 `encrypt_centered`；线性求值使用
   `add_plain_assign`、`mul_plain_to`，并显式选择 `PlaintextEmbedding`。
   随后用 `client.decrypt(&result)` 按密文绑定的 level 恢复。
4. 启用 `batching` 时，一次准备 `context.batching_encoder()`。通过 `encode_to`
   直接写入 context 分配的明文，再对恢复的多项式调用 `decode`。
5. 复用预备资源，只更换明文并使用新鲜加密随机性。基础示例选择分配返回结果的
   加密/解密便利入口；对应 `*_to` 可复用调用方输出。

两种加密 embedding 都接收 `[0,p)` 中的 N 个规范系数；`Unsigned` 直接提升，
`Centered` 使用 `[-floor(p/2),ceil(p/2))`，恢复结果为规范系数。
示例参数只验证功能，不是安全预设。

## 进阶工作流

| 示例 | 新增概念 |
| --- | --- |
| [ciphertext_multiplication](examples/ciphertext_multiplication.rs) | 一把 relin key 与 `BgvMultiplication`；两次密文系数乘法复用同一操作 |
| [leveled_coefficients](examples/leveled_coefficients.rs) | Square、`X→X^5`、Alice→Bob 换钥、明文加法和两次 prime drop |
| [leveled_slots](examples/leveled_slots.rs) | 显式 `n<N` 编码、行旋转/交换、换钥与两次 prime drop，复用输出 |
| [collective](examples/collective.rs) | 个别原生 share、公钥贡献、两轮 relin 与在线 client 交付 |

```sh
cargo run -p primus_bgv --example ciphertext_multiplication
cargo run -p primus_bgv --example ciphertext_multiplication -- --hybrid
cargo run -p primus_bgv --example leveled_coefficients
cargo run -p primus_bgv --example leveled_slots --features batching
cargo run -p primus_bgv --example collective
```

密文乘法示例默认使用 signed-radix Q keys，`--hybrid` 选择 partitioned QP keys；
基础示例不接收参数。代码中可通过克隆的 `Arc`，在各角色 key 间共享
`context.radix_key_parameters(level,config)` 或
`context.hybrid_key_parameters(level,decomposition_count,&key_p)`。
Key P 须独立纳入安全/误差预算；共享数值 metadata 本身不证明外部导入的秘密或变换来源。
见 [Native Hybrid 契约](../../guides/development/native-hybrid-keys.md)（English）。

## Level、槽与数值契约

Level0 使用完整有序 Q，level l 丢弃最后 l 个 primes，N 不变。
`try_with_levels(parameters,count)` 只准备请求的前缀。各实际 level 分别生成角色 key；
不能截断高层 key 矩阵作为低层建钥入口。Prepared multiplication、relinearizer、
switcher 与 automorphism 从角色 key 推导 level；线性求值、建钥和 prime drop
仍显式选择 level，普通恢复则从密文绑定推导。

Radix keys 在分解前先将被切换组件乘 `p^-1 mod Q`，column phase 为
`p*g_j*h+p*e_j`，近似 residual 与 key noise 都保持 p 倍数。
每组件精确 prime drop 为 `(x-p*center_q(x*p^-1 mod q))/q mod (Q/q)`；
它不同于 BFV nearest rounding，一般 prime 链不受支持。
Signed digits、截断 residual、Hybrid correction 与完整 drop 界见
[BGV 求值契约](../../guides/development/bgv-evaluation.md)（English）。

恢复精确组合所选 level 的 phase，再对 centered lift 模 p；Q 可超过128位。
**每层**的 intended integer phase 都须位于 `(-Q/2,Q/2)`。参数构造只检查
fresh-private 充分界 `p*maximum_error+(p-1) <= floor(Q/2)`；公钥及求值恢复需要
完整噪声界。每个 signed error coefficient 在所有 RNS limbs 中共享一次采样。
公钥 ephemeral r 为精确 CBD1，fresh public phase 在完整 negacyclic 环中为
`lift(m)+p*(e_pk*r+e0+e1*s)`。密文 primes 须支持实际 NTT 且满足 `q_i<2^62`；
rootability 检查不证明素性或安全性。

系数 p 可为合数。槽要求素数 `p≡1 mod 2n`；context 工厂选择 `n=N`，
`leveled_slots` 展示显式小 encoder。`embed_to` 映射 `f(Y)` 到 `f(X^(N/n))`，
秘密/误差和密文仍是完整 N。恢复后 `extract_to` 检查子环支撑，再 decode。
`encode_to` 对槽前缀补零；`encode`/`decode` 分配结果，`decode_to` 使用 caller scratch。
行旋转按 `n/2` 归一化有符号左移 steps；行交换不反转顺序。Encoder 不兼容在建钥 RNG 前
拒绝。完整契约见[编码 crate](../primus_encoding/README.zh_CN.md)和建钥 rustdoc。

## Collective 与一次性协议职责

Collective plan 借用每个 owner 的 `DcrtGlweSecretKey<u64>`，采样前检查数值 geometry、
有序 Q 和声明的 law。该族要求精确 CBD1（`SparseTernary`）share 与 CBD21 error。
建钥期间唯一持有原生秘密，实际输入/恢复时再消费进 client。两轮 state 不可克隆，
各退出路径均擦除 key-domain share 与 ephemeral。Hybrid key 的 masks/贡献使用 QP，
公钥和 additive input 仍使用 Q。

在 checked import 前认证 context、role、source/target、roster 和 round。
调用方拒绝重复/缺失 owner，绑定准确冻结的首轮结果并执行单次策略；metadata 不证明
实际 NTT 约定、CBD1 抽样或秘密关系。`BgvSeededInput` 采样独立完整均匀 A；
`try_from_common_mask` 导入已认证数组，其来源由调用方保证。公开短 seed 不是 full-ring
统计证书，A 不得复用公钥 mask，也不能从 selection/lookup key bytes 派生。
`partial_phase_to` 只产生 `c1*s_i`；外围协议负责 c0、privacy flooding、完整噪声/安全界
及 opening 授权。这些算术原语本身不构成认证 opening 协议。

## 资源与验证

Context 拥有 sampler/恢复 basis 和共享的 immutable full-Q table。
`shared_table()` / `try_with_table` 在 N/有序 Q 检查后支持 BFV/BGV 配对 context，
恢复常量仍保持各方案语义。Client 拥有一份变换域秘密和会擦除的恢复 workspace。
Prepared 操作借 context/key 并拥有 mutable scratch；并发请求各自需要操作 owner。
Prepared `*_to`/`*_assign` 求值和恢复不分配临时存储。秘密、生成时临时量、公钥
ephemeral 和恢复 scratch 遵守各自擦除合同；公钥 encryptor 可用 `Zeroize` 擦除而
保留 allocation。消费式 `into_secret_key` 转交唯一 allocation；跨方案使用仍须匹配
实际 roots/order。

`BgvEvaluator::new` 自持 plaintext scratch，是最简单的默认用法。顺序操作需要共享
worker buffer 时，可用 `with_plaintext_scratch` 借用准确的 active N·|Q| 前缀；
同一 buffer 不能借给并发操作。

公开入口按各自合同在写入/RNG 前检查完整长度及明文条件。Context 创建的密文及其
clone/view 保留本地 context 与 level；prepared key 必须来自同一 context，已绑定的错
context/level 输入和输出在写前拒绝。`client.decrypt(&ciphertext)` 直接使用该绑定，
但不证明实际同 secret 关系，也不认证通过 `AsMut` 改写的 residues。显式
`from_raw` / `zero_raw` 容器与 `decrypt_at_level` / `decrypt_at_level_to` 保留高级
调用方合同。`context.try_bind_ciphertext(raw,level)` 一次检查存储与规范性；实际变换
和 secret 来源仍由调用方保证。详见[context、level 与 raw 互操作](../../guides/development/scheme-context-binding.md)。
准确 panic、correctness 和 partial-write 合同由逐方法 rustdoc 维护。

默认 features 为空；`batching` 启用共享槽编码，`simd` 转发已有 nightly 后端。
运行期 NTT intrinsic 分派独立于该 feature；关闭 `simd` 不表示强制 scalar NTT。

`parallel` 启用已接入的建钥与 gadget-product 路径中的有界 DCRT prefix 正逆 NTT
调度。每次 prefix 的 N≥4096 且至少两条 limb 时使用至多4个连续任务；总线程数须由
`RAYON_NUM_THREADS` 或 `ThreadPool::install` 限制。默认关闭，此 NTT 路径保持串行
且不初始化 pool；随机采样保持串行。

```sh
cargo test -p primus_bgv --lib --tests --features batching
cargo clippy -p primus_bgv --all-targets --features batching -- -D warnings
cargo bench -p primus_bgv --bench leveled --features batching
```

聚焦 `workflow` bench 测公钥加密/明文求值/恢复，`leveled` 测完整 packed 请求；
setup 和 validation 在计时外。独立 DFT、schoolbook 和宽整数 oracle 保护 phase、
residual、精确商和边界契约。Feature 与独立 consumer 检查见
[测试指南](../../guides/development/testing.md)。
