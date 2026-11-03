# primus_bgv

[English](README.md) | 简体中文

固定 u64、rank-one 的 leveled BGV，支持 q_i≡1 mod p 参数族。原生密文为
`[c0,c1]`，phase 是 `c0+c1*s=lift(m)+p*e`。支持私钥/公钥加密、线性/明文求值、
乘法/square、p-preserving relin/换钥/自同构、精确 prime drop 和可选槽工作流。
Coefficient p 可以是合数；batching 另有明文素数要求。

## 使用流程

从[系数示例](examples/coefficients.rs)开始：公钥加密 `3+2X` 和 `5+X`，
做一次乘法，再恢复 `15+13X+2X²`。启用 `batching` 后运行
[槽示例](examples/slots.rs)：n=N 的密文逐槽乘法与行旋转。
[多级系数示例](examples/leveled_coefficients.rs)和
[多级槽示例](examples/leveled_slots.rs)展示 square、自同构、秘密切换和两次
prime drop；后者也展示 n<N 子环。

1. 用 `BgvParameters::try_coefficients` 构造参数，或用
   `try_with_error_distribution` 显式选择 Gaussian/CBD。`BgvContext::try_new`
   准备一层；`try_with_levels(parameters,count)` 准备显式降模链。
2. `BgvClient::generate(&context,rng)` 拥有一份完整 N 秘密和可复用、drop 时擦除的
   恢复 scratch。保留 `client.public_key(rng)`，用
   `context.public_key_encryptor(&key)` 绑定公钥。Client 与公钥 encryptor 都提供
   `encrypt`/`encrypt_centered`，只分配返回密文；预备输出使用对应 `_to` 接口。
3. 生成 `relinearization_key(level,config,rng)`，然后绑定
   `BgvMultiplication::try_new(&context,&key)`。Level 由 key 推导；
   `multiply_to`、`square_to` 和 `square_assign` 复用内部 scratch 完成 tensor
   乘法与重线性化，在线不分配。
4. 线性/明文运算使用 `BgvEvaluator::new(&context,level)`。add/sub/neg 操作两个
   组件，add_plain 只改 c0，mul_plain 乘两个组件；显式选择 unsigned/centered
   `PlaintextEmbedding`。高级分阶段流程仍可用 `mul_to`/`square_to` 写显式
   `BgvQuadraticCiphertext`，再由 `BgvRelinearizer` 恢复两组件密文。
5. 只生成实际需要的 `automorphism_key`、`key_switching_key`，预先绑定
   `BgvAutomorphism` 或 `BgvKeySwitcher`。由目标 client 从 source client 生成换钥
   材料；自同构 key 把 σ(s) 切换回 s。
6. `BgvModulusSwitch::new(&context,level).switch_to` 丢弃相邻末 prime。随后用
   `client.decrypt_to(input,level,&mut output)` 恢复；便利 `decrypt` 只分配结果。
   这些操作不自动选择噪声策略或降模时机。

Level0 使用全部有序 primes；level l 丢弃最后 l 个。Context 拥有一张 full-Q NTT 表
及各 prefix 的真实 CRT base/恢复常数；单份 full-Q secret 按 prefix 借用，N 不变。
存储 wrapper 检查完整长度，但实际 key、有序 basis、canonical ciphertext residues
及 NTT 身份仍由调用者保证。

## 求值密钥与精确降模

使用已有 `DecompositionConfig` 选择 radix 和 retained digits。每个 role key 拥有
实际 decomposition，并属于一个 modulus level；按所需 level 分别生成。不能截断
高层 key 的 limbs 冒充低层 key，因为 Q、weights 和 dropped bits 已改变。`None`
选择全部可用 gadget digits；当 log_basis 不整除 Q 位宽时，仍会丢弃低 bits。

被切换组件 a 在分解前先乘 Q 下的 p^-1；column phase 为 `p*g_j*h+p*e_j`，
h 分别为 s²、source secret 或 σ(s)。Digit noise 与近似 residual 都成为 p 倍误差，
不能直接照搬普通截断 BFV/GLWE 切换。三种 key 类型防止 relin/换钥/自同构角色误配；
构造器拒绝错误 level、N、p 或有序 Q；实际 decomposition 和 columns 由各 role
实现持有。同参数下的实际 secret 身份仍是 caller 契约。

丢末 prime q 的每组件精确商为 `(x-p*center_q(x*p^-1 mod q))/q mod (Q/q)`。
只需 dropped limb INTT、一份 N scratch、各 retained limb correction NTT 和 inverse
factors；它不同于 BFV nearest rounding。q≡1 mod p 使目标链无需额外明文 correction
factor，一般 primes 仍被拒绝。[BGV 求值契约](../../guides/development/bgv-evaluation.md)
给出 phase/residual/noise 推导及共享 componentwise GLev adapter 的边界。

## 精确恢复与噪声

每个 signed error coefficient 在所有 RNS limbs 中共享一次真实采样，随后乘 p。
Gaussian/CBD 使用实际配置分布；公钥 ephemeral r 独立采用准确 CBD1。公钥 phase 是
p*e_pk，fresh public phase 为完整 negacyclic 环中的
`lift(m)+p*(e_pk*r+e0+e1*s)`。

恢复在所选 level 计算 phase/INTT，精确重构 x∈[0,Q)：下半区返回 x mod p，上半区
返回 (x-Q) mod p。Q 可超过 128 位，不调用 BFV decoder、浮点近似或外部 BigInt
normal 依赖。**每一层**的 intended integer phase 都必须位于 (-Q/2,Q/2)，跨 Q 的
wrap 可能改变模 p 消息。

参数构造只检查 fresh-private 充分界 `p*maximum_error+(p-1) <= floor(Q/2)`。
准备低层、生成 evaluation key 和跑通功能例子，不证明 public/evaluated 噪声或安全性。
分析须包括 full-ring 卷积、message carry、每次分解 residual 和 prime-drop correction；
相关 evaluation keys 另有对应安全假设。密文 q_i 必须是适配当前 u64 NTT 的素数
（q_i<2^62），rootability 检查不等于素性认证。

## 槽与子环

可选 `batching` 使用 BFV 同样消费的共享 `primus_encoding::BatchingEncoder`。
素数 p≡1 mod 2n 提供 ±5^j 两行的 n 槽。`encode_to` 对槽前缀补零，`embed_to`
映射 f(Y)→f(X^(N/n))；只有明文使用 n，实际秘密、误差、变换和密文保持 N。
基础 n=N 示例直接编码到完整明文多项式，恢复后直接 decode。n<N 流程在 Full-N
恢复后用 `extract_to` 验证子环支撑，再用 caller scratch decode；此时 p 不必
支持 full-N plaintext NTT。

用 `rotation_exponent(k)` 或 `row_swap_exponent()` 选择奇数 full-ring automorphism
key，再由 `BgvAutomorphism::apply_to` 真正执行密文操作并切回原秘密。多级槽例使用
n32/N128/p193，旋转/交换两行并换到第二个 full-N secret；spare slots 在置换后的
位置仍全部为零。

## 资源与命令

Context 拥有 sampler/bases/table，client/evaluator/prepared key operations 借用它。
Prepared 加密、tensor/square、线性/明文求值、relin/换钥/auto、相邻 prime drop 和
恢复均不新增分配。秘密、生成时 secret-square/automorphism 临时值、公钥 ephemeral
及恢复存储按契约擦除。可用 `Zeroize::zeroize` 显式擦除公钥 encryptor ephemeral，
保留完整预备 allocation；caller 明文/输出/batching buffers 由其拥有者管理。不新增
Domain 或系数字类型泛型。

默认 features 为空；`batching` 启用共享槽编码，`simd` 转发已有 nightly SIMD 后端。

```sh
cargo run -p primus_bgv --example coefficients
cargo run -p primus_bgv --example slots --features batching
cargo run -p primus_bgv --example leveled_coefficients
cargo run -p primus_bgv --example leveled_slots --features batching
cargo test -p primus_bgv --features batching --lib --tests
cargo clippy -p primus_bgv --all-targets --features batching -- -D warnings
cargo bench -p primus_bgv --bench leveled --features batching
```

测试用 direct DFT、schoolbook 卷积和独立任意宽整数 oracle 检查 key phases、signed
gadget digits/residuals、精确商和偶数 p 边界。`leveled` 基准测一次完整 fresh packed
请求，包含乘法/square/relin、旋转、秘密切换、两次 prime drop 和槽恢复；setup/
建钥/分配与最终断言在计时外。较小的 `workflow` 保留原公钥加密/明文求值/恢复负载。
参数为功能 fixtures，不是安全预设。
