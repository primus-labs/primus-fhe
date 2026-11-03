# primus_bfv

[English](README.md) | 简体中文

BFV 系数和槽加密/求值采用原生组件 `[c0,c1]`，phase 为
`c0+c1*s=delta*lift(m)+e`，其中 `delta=floor(Q/t)`。Rank-one 后端使用
`u64` 残数、`BarrettModulus<u64>` 和 `U64DcrtTable`，总模数 Q 可以超过
64 位。算术、NTT、sampler、秘密存储及编码复用底层 crate。
可选 `batching` 启用共享槽编码。

## 系数工作流

先运行[系数示例](examples/coefficients.rs)：一次 setup 复用两次公钥加密、密文乘法和系数恢复请求。

```sh
cargo run -p primus_bfv --example coefficients
```

1. 用 `BfvParameters::try_coefficients(N,t,&Q,secret_law,sigma)` 构造参数，
   移入 `BfvContext::try_new(parameters)`。
2. 生成 `BfvClient::generate(&context,rng)`，调用 `client.public_key(rng)`，
   绑定 `context.public_key_encryptor(&public_key)`。
3. 用 `context.new_plaintext()`、`context.new_ciphertext(level)` 准备输出，
   从 context 推导完整长度。
4. 生成 `client.relinearization_key(level,config,rng)`，一次性准备
   `BfvMultiplication::try_new(&context,&relin_key)`。`multiply_to`、`square_to`
   输出普通 degree-one 密文；`square_assign` 复用输入输出。
   缩放及重线性化所需的内部 scratch 可持续复用。
5. 每次请求复用 setup 和预备乘法 owner。基础例使用分配结果的 `encrypt_centered`、
   `decrypt`，`multiply_to` 复用输出；需要调用方缓冲区和在线零分配时改用
   `encrypt_centered_to`、`decrypt_to`。

乘法从 key 推导 level，自动准备仅用于计算的辅助 primes；它们不扩大加密/密钥模数。
示例参数只演示功能，不是安全参数配置。完整电路恢复需要覆盖全部累积误差的界限。

两种加密 embedding 都接受恰好 N 个 `[0,t)` 规范值。Unsigned 将 m 提升为 m；
centered 使用 `[-floor(t/2),ceil(t/2))`。恢复返回 `[0,t)` 中的规范系数。
`client.encrypt`、`encrypt_centered` 也提供私钥加密。分配式加密/解密适合单次调用；
预备后的 `*_to` 接口复用调用方输出。

## 槽

启用 `batching`，运行[槽示例](examples/slots.rs)。它先使用 `n=N`，直接编码两个
槽向量，执行密文乘法，再通过加密自同构密钥将每行旋转一位。两次请求复用 setup、
预备操作和求值输出；`encode`、`decode`、加密和恢复则分配各自结果。高级例和
benchmark 用 `*_to` 配合可复用 scratch。

```sh
cargo run -p primus_bfv --example slots --features batching
```

`context.batching_encoder()` 从 context 的 N/t 准备已有 `BatchingEncoder`，
由它拥有唯一 plaintext NTT table，context 不另存缓存或 clone。
`client.row_rotation_key(level,&encoder,steps,config,rng)` 按 signed steps
生成行旋转密钥：正值向左、负值向右，按每行长度环绕；`row_swap_key` 交换两行。
两者都用 `BfvAutomorphism::try_new(&context,&key)` 绑定，自动从 key 推导 level。
Encoder 的模数或容量错配在随机采样前拒绝。

高级[子环槽示例](examples/subring_slots.rs)和[多级槽示例](examples/leveled_slots.rs)
将 `n<N` 明文嵌入完整环，秘密和密文仍为 N；即使当前明文模数不支持 full-N
batching，仍可显式准备合法的较小 encoder。未使用槽及 off-stride padding 为零。
一般 `automorphism_key` 和 encoder 的 exponent 方法继续供显式多项式替换使用。

## 求值与层级

`BfvEvaluator::new(&context,level)` 处理密文加、减、取负和明文加/乘。
明文操作显式选择 `PlaintextEmbedding`：加法恰好乘一次 delta；乘法使用
**未缩放**的明文 lift。由于 `delta*t` 不一定等于 Q，消息模 t 约简会引入编码漂移。

用 `BfvContext::try_with_levels(parameters,level_count)` 准备前缀模数链。
数量包含 level 0；level l 去掉最后 l 个 primes。
`BfvModulusSwitch::new(&context,source_level).switch_to` 通过精确系数级最近舍入
去掉最后一个 prime。各目标层有自己的 codec，必须满足该层完整误差界限。

原生角色密钥分别实现重线性化、source→recipient 换钥和加密自同构。
Prepared 构造器接收 `(&context,&key)`，从 key 推导适用 level；key generation、
不绑定 key 的线性求值、降模和恢复仍显式选择实际 level。
每个实际使用的 level 都要独立建钥。BFV key column 的 phase 为 `g_j*h+e_j`；
截断分解 residual 和 key noise 都消耗恢复余量，最大 digit 数也不一定消除全部
radix 余位。[多级系数](examples/leveled_coefficients.rs)和
[多级槽](examples/leveled_slots.rs)组合演示乘法、square、旋转、Alice→Bob 换钥及两次降模。

## 精确乘法与恢复

乘法先保留 centered **整数** negacyclic 组件乘积，再精确计算
`round(t*T_i/Q) mod Q`。RNS NTT 实现准备满足 `P>N*Q` 的辅助基 P；
若先把 tensor 模 Q，就会丢失缩放所需的整数倍数。实现采用精确 CRT 和商恢复，
不用浮点舍入。独立整数 schoolbook 算法和 raw tensor 检查保留为私有数学验证，
不为 test/bench 额外公开内部表示访问器。

高级调用方可用 `BfvMultiplication::try_with_auxiliary_moduli(context,key,&primes)`
指定 P；需要已缩放的 quadratic 中间结果时，可显式使用 `BfvMultiplier` 和
`BfvRelinearizer`。构造器检查容量、互素及 NTT 兼容性；自选 prime 的素性仍是
调用方前提。[求值契约](../../guides/development/bfv-evaluation.md)（English）
推导整数 lift 界限、精确商恢复和完整 phase 误差。

Codec **在恢复界限内得到精确消息**，不是任意 phase 的精确舍入 oracle。
对于 `delta*m+e`，充分条件为 `abs(t*e-(Q%t)*m)/Q+k/gamma<1/2`，k 为 Q 的 prime 数。
`codec(level).validate_noise_bound` 检查覆盖全部消息的保守界限。
`try_coefficients` 使用解码辅助模数 `gamma=2^61-1`，要求 `t<gamma`；
`try_new` 可选择 gamma，`try_with_error_distribution` 还可选择误差分布。
构造器检查 codec 条件，并用 sampler 的完整支撑验证 fresh 私钥恢复充分条件；
不证明安全级别、公钥加密恢复或求值恢复。必须计入公钥噪声、fixed-delta 漂移、
全部求值项和每次降模的舍入误差。

## 高级显式工作流

[显式系数示例](examples/explicit_coefficients.rs) 展示 borrowed
`BfvSecretKeyContext`、显式 `U64DcrtTable`、复用输出和 `BfvDecryptWorkspace`。
其他工作流已经拥有变换域秘密/table 时可使用这些绑定。`size()` 维护 geometry；
`base_q()` 维护 basis 算术；`codec()` 维护缩放/恢复常量；
`encryption_parameters()` 维护 sampler。

Raw GLWE 保留 `[a,b]` 和 phase `b-a*s`。`write_raw_glwe_to` 写出
`[a=-c1,b=c0]`；`set_from_raw_glwe` 导入 `[c0=b,c1=-a]`，复制并取负规范残数，
不分配、不执行 NTT。[Hybrid-RNS 示例](examples/hybrid_rns_key_switch.rs)的
switching/GGSW keys 保持 raw 语义，因此消费这些桥接。
`gadget_parameters` 为这些真实 raw 消费者准备不含 codec 的分解权重。
显式 secret/public 加密绑定还接受系数域 CRT 输入：
`encrypt_plaintext_lift_crt_to` 接受**未缩放**的 canonical lift，恰好乘一次 delta；
`encrypt_encoded_crt_to` 接受**已经缩放**的 phase，不再乘 delta。将 codec 输出传入
lift 入口会重复缩放。CRT limbs 按 modulus-major Q 顺序排列。

符号和噪声项见 [RNS phase 约定](../../guides/development/rns-phase-conventions.md)（English）。

## 资源与检查

Context 拥有 Q tables、samplers 和请求的 codecs。Client 拥有一份最高层变换域秘密
及恢复 workspace；低层恢复借用其前缀。预备操作借用不可变 context/key，自持可变
scratch。独立并发请求使用独立的可变操作 owner。预备后的 `*_to`、`*_assign`
不分配临时存储；构造器及分配式加密/解密会分配。秘密和 ephemeral/恢复 scratch
在 drop 时擦除。`encryptor.zeroize()`、`Zeroize::zeroize(&mut decrypt_workspace)`
保留 allocation 和 geometry。

加密在消耗 RNG 或写入前检查完整长度及 canonical 明文；evaluator 明文入口在
写入前检查。密文携带存储，不携带已认证的 level、secret 或变换身份。调用方需要
使用实际 level、规范 NTT 残数、一致的 roots/order 及实际系数秘密。长度/模数相同
不能证明这些身份。优化 Q primes 须支持 NTT 且小于 `2^62`。
精确契约和 partial-write 行为以方法 rustdoc 为准。

默认 features 为空。`simd` 转发到底层后端，遵循其 nightly 要求。

```sh
cargo check -p primus_bfv --all-targets --features batching
cargo test -p primus_bfv --lib --tests --features batching
cargo clippy -p primus_bfv --all-targets --features batching -- -D warnings
cargo run -p primus_bfv --example explicit_coefficients
cargo run -p primus_bfv --example hybrid_rns_key_switch
cargo run -p primus_bfv --example leveled_coefficients
cargo run -p primus_bfv --example leveled_slots --features batching
cargo bench -p primus_bfv --bench multiplication --features batching
```

小参数测试采用独立 direct-DFT、schoolbook 和整数舍入 oracle；私有表示检查留在
私有测试模块。覆盖 phase、稠密乘积、边界、raw 桥接、错误检查、workspace
复用/擦除及分配契约。Criterion 测量公开预备操作和完整 fresh 请求，setup 位于计时外。
历史测量及其源码/负载限制见[性能报告](../../guides/performance/bfv-multiplication.md)（English）。
