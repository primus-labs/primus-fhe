# primus_bgv

[English](README.md) | 简体中文

固定 u64、rank-one 的 leveled BGV，支持与明文模数 p 互素的一般密文素数。原生密文为 `[c0,c1]`，phase 是 `c0+c1*s`；意图中的整数代表为 `z=lift(f*m mod p)+p*e`。恢复要求 z 位于 `(-Q/2,Q/2)`，使原生 phase 的 centered lift 等于 z；规范且可逆的 correction factor f 随密文的实际运算历史变化。提供私钥/公钥加密、线性/明文求值、乘法、重线性化、换钥、自同构、prime drop 和可选槽工作流。

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
| [leveled_coefficients](examples/leveled_coefficients.rs) | 生成普通 primes、公开电路预算、square、`X→X^5`、Alice→Bob 换钥与两次 drop；`--hybrid` 选择实际 QP keys |
| [leveled_slots](examples/leveled_slots.rs) | 显式 `n<N` 编码、行旋转/交换、换钥与两次 prime drop，复用输出 |
| [collective](examples/collective.rs) | 个别原生 share、公钥贡献、两轮 relin 与在线 client 交付 |

```sh
cargo run -p primus_bgv --example ciphertext_multiplication
cargo run -p primus_bgv --example ciphertext_multiplication -- --hybrid
cargo run -p primus_bgv --example leveled_coefficients
cargo run -p primus_bgv --example leveled_coefficients -- --hybrid
cargo run -p primus_bgv --example leveled_slots --features batching
cargo run -p primus_bgv --example collective
```

密文乘法示例默认使用 signed-radix Q keys，`--hybrid` 选择 partitioned QP keys；
基础示例不接收参数。代码中可通过克隆的 `Arc`，在各角色 key 间共享
`context.radix_key_parameters(level,config)` 或
`context.hybrid_key_parameters(level,decomposition_count,&key_p)`。
Key P 须独立纳入安全/误差预算；共享数值 metadata 本身不证明外部导入的秘密或变换来源。
见 [Native Hybrid 契约](../../guides/development/native-hybrid-keys.md)（English）。

## 生成参数与声明电路的准入

`BgvParameterRequest::create_context` 根据显式 N、p、prime 字宽/数量、levels
与采样 law 生成并验证实际全环 NTT primes，不要求 `q_i≡1 (mod p)`。随后 `BgvCircuitPlan::try_new(&context,&operations,backend)` 为声明的普通静态电路逐节点准入，给出 correction factor、完整整数 phase、误差包络、分项贡献、居中恢复容量及剩余 margin。拒绝包含节点、level 与所需模数位数，调用方据此调整显式资源选择。

通过 `plan.key_config(level)` 生成账本实际覆盖的普通 relin、自同构与换钥 key。
`BgvBudgetBackend::hybrid` 生成独立 key P，并在 `plan.security_inputs()` 中列出
实际使用各层的 QP 暴露域。这些是独立安全估算的精确公开输入，状态保持
`NotEvaluated`；生成、准入或解密成功均不表示达到 128 位安全。
预算采用采样硬支持与全环卷积界，覆盖重复/相关输入和 key，但可能保守地拒绝
实际可运行电路。它仅覆盖声明的普通操作，不适用于 collective key、raw SSLE
运算或隐私 opening。公式见[公开电路预算](../../guides/development/bgv-evaluation.md#public-static-circuit-budgets)（English），
完整流程与离线筛查见[参数与安全参考指南](../../guides/development/ordinary-parameter-budgets.md)。

## Level、槽与数值契约

Level0 使用完整有序 Q，level l 丢弃最后 l 个 primes，N 不变。
`try_with_levels(parameters,count)` 只准备请求的前缀。各实际 level 分别生成角色 key；
不能截断高层 key 矩阵作为低层建钥入口。Prepared multiplication、relinearizer、
switcher 与 automorphism 从角色 key 推导 level；线性求值、建钥和 prime drop
仍显式选择 level，普通恢复则从密文绑定推导。

Fresh 加密的 factor 为 f=1。密文乘法将两个输入 factor 相乘并模 p，prime drop 将 f 更新为 `f*q^-1 mod p`；relinearization、换 secret 与自同构保留 factor。因此，同 level 的密文也可能有不同 factor；加减法会先用公开的 centered scalars 对齐，明文加法则注入 factor 加权的消息 lift，相应尺度计入求值 phase 界。外部消费者需要时读取 `ciphertext.correction_factor()`，不能只按 level 推断。

Radix keys 在分解前先将被切换组件乘 `p^-1 mod Q`，column phase 为
`p*g_j*h+p*e_j`，近似 residual 与 key noise 都保持 p 倍数。
每组件精确 prime drop 为 `(x-p*center_q(x*p^-1 mod q))/q mod (Q/q)`；
它不同于 BFV nearest rounding，通过上述 factor 更新支持一般互素 prime 链。Signed digits、截断 residual、Hybrid correction 与完整 drop 界见
[BGV 求值契约](../../guides/development/bgv-evaluation.md)（English）。

恢复精确组合所选 level 的 phase，对 centered lift 模 p 后再乘 f 在模 p 下的逆；Q 可超过128位。**每层**的 intended integer phase 都须位于 `(-Q/2,Q/2)`。参数构造只检查
fresh-private 充分界 `p*maximum_error+(p-1) <= floor(Q/2)`；公钥及求值恢复需要
完整噪声界。每个 signed error coefficient 在所有 RNS limbs 中共享一次采样。
公钥 ephemeral r 为精确 CBD1，fresh public phase 在完整 negacyclic 环中为
`lift(m)+p*(e_pk*r+e0+e1*s)`。密文 primes 须支持实际 NTT 且满足 `q_i<2^62`；
rootability 检查不证明素性或安全性。

系数 p 可为合数，但每个密文 prime 和 correction factor 都须与 p 互素。槽要求素数 `p≡1 mod 2n`；context 工厂选择 `n=N`，
`leveled_slots` 展示显式小 encoder。`embed_to` 映射 `f(Y)` 到 `f(X^(N/n))`，
秘密/误差和密文仍是完整 N。恢复后 `extract_to` 检查子环支撑，再 decode。
`encode_to` 对槽前缀补零；`encode`/`decode` 分配结果，`decode_to` 使用 caller scratch。
行旋转按 `n/2` 归一化有符号左移 steps；行交换不反转顺序。Encoder 不兼容在建钥 RNG 前
拒绝。完整契约见[编码 crate](../primus_encoding/README.zh_CN.md)和建钥 rustdoc。

Flexilect 仍采用独立的 `q_i≡1 mod p` 降模策略、factor1 密文及 `Q=p*Delta+1` 桥接/噪声契约；其准入层在使用通用 BGV 核心时继续保留这些约束。

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
`partial_phase_to` 只产生物理贡献 `c1*s_i`，不去除 f。外围协议将 factor 与完整密文共同认证，并负责 c0、privacy flooding、完整噪声/安全界及 opening 授权；合成所有物理份额后，才对 centered phase 模 p 并统一去除一次 f。这些算术原语本身不构成认证 opening 协议。

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
clone/view 保留本地 context、level 与 correction factor；prepared key 必须来自同一 context，已绑定的错
context/level 输入和输出在写前拒绝。`client.decrypt(&ciphertext)` 直接使用该绑定，
但不证明实际同 secret 关系，也不认证通过 `AsMut` 改写的 residues。显式
`from_raw` / `zero_raw` 容器与 `decrypt_at_level` / `decrypt_at_level_to` 保留高级
调用方合同，并声明 factor1。`context.try_bind_ciphertext(raw,level)` 一次检查存储与规范性。不同 factor 的外部密文通过 `context.try_import_ciphertext(words,level,factor)` 导入：它另外检查 `0<factor<p` 且 `gcd(factor,p)=1`，再绑定 context/level；调用方仍须认证该 scalar，并保证实际变换和 secret 来源。

```rust,ignore
let imported = context.try_import_ciphertext(received_words, level, received_factor)?;
let message = client.decrypt(&imported);
// 直接传入 prepared 输出容器，factor 与数据一起更新。
evaluator.add_to(&left, &right, &mut output);
```

`as_view()` 保留不可变元数据。Prepared 输出直接传 `&mut ciphertext`；旧 `as_mut_view()` 便利入口已退休，避免操作只更新临时元数据副本而使 owner 的 factor 过期。详见[context、level 与 raw 互操作](../../guides/development/scheme-context-binding.md)。准确 panic、correctness 和 partial-write 合同由逐方法 rustdoc 维护。

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
