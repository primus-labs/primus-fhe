# primus_bfv

[English](README.md) | 简体中文

采用原生组件 `[c0,c1]`、phase `c0+c1*s` 的 BFV 系数/槽加密、线性/明文求值、精确整数密文乘法与
rounded modulus switching。Rank-one 后端使用 `u64` 残数、`BarrettModulus<u64>`
和 `U64DcrtTable`；总模数 Q 可以超过 64 位。与 `primus_glwe_rns` 共享秘密存储
时，实际系数秘密不变。

本 crate 负责 BFV 参数、context、密文/公钥语义、client 和 evaluator。
可选 `batching` 消费共享槽编码；原生重线性化、换钥和密文自同构使用各自角色的密钥。
系数 codec 保留在 `primus_encoding`；
算术、NTT、sampler 和秘密存储复用底层实现。

## 系数工作流

运行完整的[多级示例](examples/leveled_coefficients.rs)：

```sh
cargo run -p primus_bfv --example leveled_coefficients
```

1. 用 `BfvParameters::try_coefficients(N, t, &Q, secret_law, sigma)` 构造参数，
   默认解码辅助模数为 `gamma=2^61-1`。高级调用方可通过 `try_new` 指定 gamma，
   或通过 `try_with_error_distribution` 指定 gamma 和 Gaussian/CBD 误差分布。
   所有构造器都会验证 codec 的互素/恢复条件；便利入口要求 `t < gamma`。
2. 将参数移入 `BfvContext::try_new`，只准备最高层；或者通过
   `try_with_levels(parameters, level_count)` 准备前缀模数链。数量包含第 0 层：
   level 0 使用完整 Q，level `l` 去掉末尾 `l` 个 prime。只准备请求的低层 codec。
3. 用 `BfvClient::generate(&context, rng)` 生成 client，或通过
   `try_from_secret_key` 移入已有的变换域秘密。公钥加密先调用
   `client.public_key(rng)`，再绑定 `context.public_key_encryptor(&public)`。
4. 用 `context.new_ciphertext(level)` 和 N 系数明文输出一次性分配缓冲区，
   通过 `client.encrypt_to`、`encrypt_centered_to` 和
   `decrypt_to(ciphertext, level, output)` 复用。
5. 用 `BfvEvaluator::new(&context, level)` 绑定密文加、减、取负，以及明文加法
   和稠密 negacyclic 明文乘法。准备 `BfvModulusSwitch::new(&context, source_level)`，
   通过 `switch_to` 去掉最后一个 prime，输出到下一个已准备的 level。

两种系数 embedding 都接受恰好 N 个 `[0,t)` 中的规范值。Unsigned 将 m 提升为 m；
centered 使用 `[-floor(t/2), ceil(t/2))`。解密返回 `[0,t)` 中的规范值。
这些是系数，不是 slots。`BfvCiphertext::as_view` 和 `as_mut_view` 借用原始存储，
无需复制。

## 缩放与求值

加密满足 `c0+c1*s = delta*lift(m)+e (mod Q)`，其中 `delta=floor(Q/t)`。
私钥加密直接计算 `c0=delta*lift(m)+e-c1*s`，在 c0 唯一一次 NTT 前将编码
融合进系数噪声。原生公钥加密计算 `c0=pk0*u+e0+delta*lift(m)`、
`c1=pk1*u+e1`，复用一个 ephemeral 多项式，每个含噪组件变换一次。
普通操作保持原生 BFV 存储。

线性运算分别作用于两个组件。`add_plain_to`/`add_plain_assign` 将当前层
乘过 delta 的明文 lift 加入 c0，保留 c1。`mul_plain_to`/`mul_plain_assign`
用**未缩放**的明文 lift 乘两个组件，实现 `Z_t[X]/(X^N+1)` 中的乘法。
明文运算显式传入 `PlaintextEmbedding`；centered lift 可以降低噪声放大。
当 `delta*t != Q` 时，消息算术模 t 约简会引入编码漂移。

从 Q 到 `Q'=Q/p` 的 switch 对每个组件执行精确的系数级最近舍入
`round(c_i/p) mod Q'`。p 为奇数，整数输入不存在半整数平局。
实现使用被丢弃残数的精确 centered lift，不使用 approximate Hybrid-RNS ModDown；
只对被丢弃 limb 执行 INTT，再将其修正项变换到保留 limbs。
Switch 引入组件舍入和缩放差异误差；每个目标层都需要独立满足完整恢复界限。
代数、符号和噪声贡献见
[RNS phase 约定](../../guides/development/rns-phase-conventions.md)（English）。

## 密文乘法与求值密钥

一次性准备 `BfvMultiplier::try_new(&context,level,&auxiliary_primes)`。
计算用 NTT 辅助基 P 要求 `P>N*Q`；构造器检查容量、互素和变换兼容性。
这些 primes 不进入秘密、密钥、codec 或 level chain。`multiply_to` 和 `square_to`
输出到 `context.new_quadratic_ciphertext(level)`，逐组件精确执行
`round(t*T_i/Q)`。需要分阶段使用时，通过 `new_raw_tensor`、`mul_raw_to`/
`square_raw_to` 和 `scale_and_round_to` 保留整数乘积。Raw tensor 不能传入
relinearizer；已缩放的 degree-two 输出也必须先重线性化才能普通求值或恢复。

默认路径采用精确 centered CRT lift、辅助 NTT 乘法与精确商恢复；不用浮点近似
half 边界，也不先模 Q 丢掉整数乘积。`BfvReferenceMultiplier::new(&context,level)`
保留独立的整数 schoolbook fallback，输出相同缩放结果，无需辅助基。
[求值契约](../../guides/development/bfv-evaluation.md)（English）推导 lift 容量、
精确商恒等式、fixed-Delta 漂移和完整 phase 误差。

生成 `client.relinearization_key(level,config,rng)` 后绑定
`BfvRelinearizer::try_new(&context,level,&key)`，用 `relinearize_to` 把 degree two
转为 degree one。`recipient.key_switching_key(&source,level,config,rng)` 为
`BfvKeySwitcher` 创建 source→recipient 换钥密钥。`automorphism_key` 接受小于
2N 的奇数指数，交给 `BfvAutomorphism` 使用。每个实际 level 独立生成密钥。
BFV columns 加密 `g_j*h+e_j`，没有 BGV 的 p 倍因子或 p^-1 预处理。
截断分解 residual 和 key noise 都消耗 BFV 恢复余量；最大 digit 数仍可能丢弃
radix 余下的低位。

## 恢复与层级

每层拥有一个 `delta=floor(Q_level/t)`、共享 t/gamma 的 codec。恢复通过
`{t,gamma}` 快速基转换和辅助修正实现，**在 codec 的恢复界限内得到精确消息**；
它不是任意 phase 的精确舍入 oracle。系数 phase 为 `delta*m+e` 时，充分条件为
`abs(t*e-(Q_level % t)*m)/Q_level + k/gamma < 1/2`，k 为该层 prime 数量。
`codec(level).validate_noise_bound` 根据完整误差幅度与 embedding 验证覆盖所有
消息的保守界限。

参数构造检查 sampling/basis 配对，并用误差分布的完整支撑验证 fresh 私钥恢复
充分条件。低层构造检查 noiseless codec 恢复。两者都不证明安全级别或公钥/求值后
恢复。目标层的完整误差必须包含公钥噪声、全部求值/漂移项，以及每次 switch 的
舍入误差。一次 fresh 加密成功不能证明整条链计算后的恢复。

密文携带存储，不携带已认证的 level、密钥或变换身份。操作检查完整长度，构造器
检查数值模数顺序和 geometry；调用方仍需保证实际 level、规范 NTT 残数、相同的
实际系数秘密，以及 context 的 roots/evaluation order。相同长度和模数不能证明
这些身份。优化 u64 NTT 后端要求 Q prime 小于 `2^62` 且与 N 兼容。

## 高级显式工作流

[加密示例](examples/coefficients.rs) 展示较低层的 `BfvSecretKeyContext`、
显式 `U64DcrtTable` 和 `BfvDecryptWorkspace` 绑定。`size()` 维护 geometry；
`base_q()` 维护 basis 算术；`codec()` 维护缩放/恢复常量；
`encryption_parameters()` 维护 sampler。其他工作流已有这些资源时，仍可使用
显式绑定。

`encrypt_plaintext_lift_crt_to` 接受**未缩放**的规范 CRT lifts，采用系数域、
modulus-major Q 顺序，恰好乘一次 delta。`encrypt_encoded_crt_to` 接受
**已经缩放**的规范 phase（包括 codec 输出），不再乘 delta。将已编码输出传入
lift 入口会重复缩放。`phase_to` 输出 DCRT，不执行 INTT 或解码；较低层
`decrypt_to` 使用显式 scratch 完成这些操作。

Raw GLWE 保留 `[a,b]` 与 `b-a*s`。`write_raw_glwe_to` 显式写出
`[a=-c1,b=c0]`；`set_from_raw_glwe` 导入 `[c0=b,c1=-a]`。边界转换复制并取负
规范残数，不分配、不执行 NTT。[Hybrid-RNS 示例](examples/hybrid_rns_key_switch.rs)
及 raw 对照基准使用这些桥接，因为现有 switching/GGSW 密钥保持 raw 语义。
`gadget_parameters` 为这些 raw 消费者准备不含 codec 的分解权重，它不是原生
BFV 求值密钥。

## 资源与验证

Context 拥有一份完整 basis 的 NTT table、一份最高层参数，以及每个请求的低层
各一份 codec。Client/evaluator 借用这些资源。Client 拥有一份最高层变换域秘密
和一份恢复 workspace；低层恢复借用它们的前缀，不复制秘密、不新建 sampler。
Workspace 包含 phase buffer，以及恰好最高层 codec 的 `decode_scratch_len(N)`
个转换元素；低层 codec 复用对应前缀。单 prime codec 不需要转换元素。

Multiplier 拥有辅助 base/table、常量和可复用 scratch，借用现有 Q 资源；只有显式
reference owner 分配整数 schoolbook workspace。Prepared key products 借用 context/
key 资源，自持分解 scratch。Evaluator 拥有一个可复用明文多项式；switch 拥有一个 N 系数 dropped-limb buffer
及预备常量。Prepared `*_to` 和 `*_assign` 操作不分配临时存储。
`new_ciphertext` 和 `decrypt` 分配返回结果。公钥 encryptor 拥有一个 ephemeral
workspace。并发操作使用独立的可变 workspace owner，可以共享不可变 context/
密钥资源。秘密和 ephemeral/恢复 scratch 在 drop 时擦除。显式
`workspace_mut().zeroize()` 或 `Zeroize::zeroize(&mut decrypt_workspace)`
保留 allocation/geometry；调用会覆盖 scratch，不在每次操作后额外扫描擦除。

完整长度错误在输出/scratch 写入或采样前拒绝。`BfvClient` 还在消耗 RNG 前检查
全部明文系数。较低层 `BfvSecretKeyContext` 和 `BfvPublicKeyEncryptor` 的系数
入口通过 codec 在噪声采样后、c0 NTT 前检查数值。Evaluator 明文入口在输出/
scratch 写入前检查全部数值。密文和 CRT 输入的表示/残数范围仍是未检查的数学
前提。RNG/NTT/codec panic 可能留下部分输出或 scratch；精确契约以方法 rustdoc
为准。

## Features 与检查

默认 features 为空。`simd` 转发到共享算术/codec 后端，遵循其 nightly SIMD 要求。

```sh
cargo check -p primus_bfv --all-targets
cargo test -p primus_bfv --lib --tests
cargo run -p primus_bfv --example leveled_coefficients
cargo run -p primus_bfv --example coefficients
cargo run -p primus_bfv --example hybrid_rns_key_switch
cargo clippy -p primus_bfv --all-targets -- -D warnings
cargo run -p primus_bfv --example leveled_slots --features batching
cargo bench -p primus_bfv --bench multiplication --features batching
cargo bench -p primus_bfv --bench leveled
cargo bench -p primus_bfv --bench public_encryption
cargo bench -p primus_bfv --bench key_switching
```

小规模功能测试通过独立 direct-DFT/schoolbook 和整数舍入 oracle 检查 phase、
稠密乘法、embedding、边界值与多级计算，还覆盖 raw 桥接、错误重复缩放、完整
检查、workspace 复用/擦除及分配契约。Criterion 在资源预备后测量独立操作和完整
加密/求值/两次 switch/解密请求。新 multiplication 基准在相同密文上比较精确 RNS NTT
与整数 schoolbook，再测量 encode/公钥加密/mul/square/relin/rotate/换钥/两次降模/
恢复/decode 的完整 fresh 请求。Raw 对照计时不包含 setup 中完成的桥接。

精确 RNS/reference 和完整请求的实际成本见
[性能报告](../../guides/performance/bfv-multiplication.md)（English）。

## 槽与明文子环

启用 `batching` 后，使用与 BGV 共用的 `primus_encoding::BatchingEncoder`，
按 ±5^j 两行转换 slot/coefficient，并把 small-n 多项式嵌入 full-N 明文。
秘密和密文仍为 N，未用 slots 和 off-stride padding 均为零。
[slots 示例](examples/slots.rs) 展示公钥加密→plaintext add/mul→精确 prime drop→
full-N 解密→extract/decode。[完整多级槽示例](examples/leveled_slots.rs) 还执行
ct×ct、square、relin、行旋转/交换、跨 client 换钥和两次降模。

```sh
cargo run -p primus_bfv --example slots --features batching
```
