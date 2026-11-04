# primus_bgv

[English](README.md) | 简体中文

固定 u64、rank-one 的 leveled BGV，支持 q_i≡1 mod p 参数族。原生密文为
`[c0,c1]`，phase 是 `c0+c1*s=lift(m)+p*e`。支持私钥/公钥加密、线性/明文求值、
乘法/square、p-preserving relin/换钥/自同构、精确 prime drop 和可选槽工作流。
Coefficient p 可以是合数；batching 另有明文素数要求。

## 使用流程

从[系数示例](examples/coefficients.rs)开始：公钥加密 `3+2X` 和 `5+X`，
做一次乘法，再恢复 `15+13X+2X²`。启用 `batching` 后运行
[槽示例](examples/slots.rs)：n=N 的密文逐槽乘法与行旋转。两个基础例都只准备一次
keys 和操作 scratch，然后使用分配便利接口执行两次请求。
[多级系数示例](examples/leveled_coefficients.rs)和
[多级槽示例](examples/leveled_slots.rs)展示 square、自同构、秘密切换和两次
prime drop；后者也展示 n<N 子环。

1. 用 `BgvParameters::try_coefficients` 构造参数，或用
   `try_with_error_distribution` 显式选择 Gaussian/CBD。`BgvContext::try_new`
   准备一层；`try_with_levels(parameters,count)` 准备显式降模链。
   `context.new_plaintext()` 从 context 推导 N，分配完整系数明文。
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
5. 槽行旋转使用 `client.row_rotation_key(level,&encoder,steps,config,rng)`，steps
   支持正负；交换两行使用 `row_swap_key`。一般多项式映射保留 `automorphism_key`，
   秘密切换使用 `key_switching_key`。预先绑定
   `BgvAutomorphism::try_new(&context,&key)` 或 `BgvKeySwitcher::try_new(&context,&key)`，
   这两者与 `BgvRelinearizer` 均从 role key 推导 level。由目标 client 从 source client
   生成换钥材料；自同构 key 把 σ(s) 切换回 s。
6. `BgvModulusSwitch::new(&context,level).switch_to` 丢弃相邻末 prime。随后用
   `client.decrypt_to(input,level,&mut output)` 恢复；便利 `decrypt` 只分配结果。
   这些操作不自动选择噪声策略或降模时机。

Level0 使用全部有序 primes；level l 丢弃最后 l 个。Context 拥有一张 full-Q NTT 表
及各 prefix 的真实 CRT base/恢复常数；单份 full-Q secret 按 prefix 借用，N 不变。
存储 wrapper 检查完整长度，但实际 key、有序 basis、canonical ciphertext residues
及 NTT 身份仍由调用者保证。

## Collective 算术

[collective](examples/collective.rs) 展示两个 owner 准备 native 公钥与两轮
relinearization key，然后直接使用已有 evaluator；不会构造聚合秘密。
`BgvCollectivePublicKey`、`BgvCollectiveSwitchingKey`、
`BgvCollectiveAutomorphismKey` 和 `BgvCollectiveRelinearization` 各自拥有具体
common-mask/basis setup，每方只提供自己的 share。首版要求精确 CBD1
（`SparseTernary`）share 与 CBD21 error；一般单方 API 仍使用原配置分布。

公开 contribution 只导出后端拥有格式的规范 residue。调用方认证 context、role、
source/target identity 与 roster 后，再经对应 setup 导入。Accumulator 检查具体
setup 实例和轮次，重复、缺失 owner 由协议拒绝。两轮私有 state 借用本方 client、不可克隆，在消费或
丢弃时擦除 CBD1 ephemeral；第二轮绑定准确冻结的第一轮结果。
Finalize 消费公开聚合，直接生成已有 native role key，不保留 setup workspace；实际
gadget weights 和 columns 不公开。

`BgvSeededInput::try_new(context, rng)` 用 prepared 无偏 CRT distributions 新鲜采样
完整公共 mask；`try_from_common_mask` 导入已认证的数组，其独立均匀来源由调用方保证。
聚合 centered input bodies 后只插入一次 shared mask。公开数组不等于公开 RNG 内部
seed/state，也不授权复用 public-key mask；短公共 seed 本身不是 full-ring 统计证书。
`BgvClient::partial_phase_to` 仅写 `c1*s_i`，不含 c0 或 privacy noise。这些是算术
原语；独立 common mask 的生成、单次 policy、完整 roster、privacy flooding 和噪声/安全
认证由协议负责。Input masks和私有coins不得从selection公钥或fresh lookup key的
bytes/digest数值派生。

## 求值密钥与精确降模

使用已有 `DecompositionConfig` 选择 radix 和 retained digits。每个 role key 拥有
实际 decomposition，并属于一个 modulus level；按所需 level 分别生成。不能截断
高层 key 的 limbs 冒充低层 key，因为 Q、weights 和 dropped bits 已改变。`None`
选择全部可用 gadget digits；当 log_basis 不整除 Q 位宽时，仍会丢弃低 bits。

被切换组件 a 在分解前先乘 Q 下的 p^-1；column phase 为 `p*g_j*h+p*e_j`，
h 分别为 s²、source secret 或 σ(s)。Digit noise 与近似 residual 都成为 p 倍误差，
不能直接照搬普通截断 BFV/GLWE 切换。三种 key 类型防止 relin/换钥/自同构角色误配；
构造器拒绝未准备的 key level 或不同的 N、p、有序 Q；实际 decomposition 和 columns 由各 role
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

启用 `batching` 后，`context.batching_encoder()` 从已有 N/p 准备 BFV 同样消费的
共享 `primus_encoding::BatchingEncoder`。Context 不缓存第二份 encoder 或明文表；
p 不支持 full-N roots 时 factory 返回错误，系数算术仍可使用。显式 n<N packing
使用 `BatchingEncoder::try_new(n,context.parameters().plain_modulus())`。
素数 p≡1 mod 2n 提供 ±5^j 两行的 n 槽。`encode`、`decode` 分配返回结果（decode
另分配临时 scratch）；准备输出和 scratch 后使用 `encode_to`、`decode_to`。`encode_to` 对槽前缀补零，`embed_to`
映射 f(Y)→f(X^(N/n))；只有明文使用 n，实际秘密、误差、变换和密文保持 N。
基础 n=N 示例直接编码到完整明文多项式，恢复后直接 decode。n<N 流程在 Full-N
恢复后用 `extract_to` 验证子环支撑，再用 caller scratch decode；此时 p 不必
支持 full-N plaintext NTT。

`row_rotation_key` 将正负 steps 按 n/2 归一化；`row_swap_key` 交换两行而不反转。
两者在消费 RNG 前验证 encoder 的 p 与 n≤N。`BgvAutomorphism::apply_to` 执行密文
操作并切回原 full-N 秘密；一般指数选择仍显式调用 `automorphism_key`。多级槽例使用
n32/N128/p193，旋转/交换两行并换到第二个 full-N secret；spare slots 在置换后的
位置仍全部为零。

## 资源与命令

Context 拥有 sampler/bases/table，client/evaluator/prepared key operations 借用它。
Prepared `_to`/`_assign` 加密、tensor/square、线性/明文求值、relin/换钥/auto、相邻 prime drop 和
恢复均不新增分配。秘密、生成时 secret-square/automorphism 临时值、公钥 ephemeral
及恢复存储按契约擦除。可用 `Zeroize::zeroize` 显式擦除公钥 encryptor ephemeral，
保留完整预备 allocation；caller 明文/输出/batching buffers 由其拥有者管理。基础例
选择分配便利接口；高级例和基准保留 prepared 输出复用。不新增 Domain 或系数字类型泛型。

默认 features 为空；`batching` 启用共享槽编码，`simd` 转发已有 nightly SIMD 后端。
NTT intrinsic按运行时CPU能力分派，独立于此Cargo feature；关闭`simd`不表示强制scalar
NTT，见[feature边界](../../guides/development/testing.md#features-与独立消费者)。

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

高级 owner 角色转移可消费 `client.into_secret_key()`，将唯一 transformed secret allocation
交给另一已验证角色的 `BgvClient::try_from_secret_key`。原 client 被消费，恢复 scratch 随之
擦除并释放；跨方案移动前须验证完整 geometry 与实际 NTT roots/order。此接口转移所有权，
不复制私有 share。
