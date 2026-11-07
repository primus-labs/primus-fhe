# primus_bfv

[English](README.md) | 简体中文

固定 `u64`、rank-one RNS 上的 BFV 系数与 slots 加密/求值。
密文存储 `[c0,c1]`，phase 为 `c0+c1*s=delta*lift(m)+e`，其中
`delta=floor(Q/t)`。`u64` 表示单个 residue，Q 的乘积可超过64位。
算术、NTT、采样、秘密存储和编码复用底层 crate。

## 系数与 slots

从 [coefficients](examples/coefficients.rs) 开始：公钥加密多项式，加明文常数，
再乘明文 scalar 并恢复系数。两个请求复用同一 setup，不需要 evaluation key。

```sh
cargo run -p primus_bfv --example coefficients
cargo run -p primus_bfv --example slots --features batching
```

两个基础示例采用相同的调用链：

1. 用 `BfvParameters::try_coefficients(N,t,&Q,secret_law,sigma)` 建立参数，
   消费进 `BfvContext::try_new(parameters)`。
2. `BfvClient::generate(&context,rng)` 生成本方 client，保留
   `client.public_key(rng)`，绑定 `context.public_key_encryptor(&public_key)`。
3. 用 `context.new_plaintext()` 和 `context.new_ciphertext(level)` 准备输入/输出，
   一次构造 `BfvEvaluator::new(&context,level)`。
4. 加密后，用 `add_plain_to` / `mul_plain_to` 显式选择 `PlaintextEmbedding`，
   最后 `client.decrypt(&ciphertext)` 按密文绑定的 level 恢复。下个请求复用 setup 和输出，
   重新采样加密随机性。

[Slots](examples/slots.rs) 增加一个 `context.batching_encoder()`，采用 n=N。
`encode_to` 直接写入 context 的明文多项式；解密后用 `decode` 恢复 slots。
Encoder 自持 plaintext NTT table，应跨请求保留。基础示例选择分配式加密/恢复；
prepared `*_to` 支持复用调用方输出。示例的小参数只验证功能，不是安全 preset。
Full-ring packing 要求明文素数 t≡1 mod 2N；subring 示例仅将明文放在 n<N 环，
秘密和密文始终保留完整 N。

## 选择进阶工作流

| 需求 | 入口与新增资源 |
| --- | --- |
| 密文乘法 | [ciphertext_multiplication](examples/ciphertext_multiplication.rs)：一把 relinearization key 和 `BfvMultiplication`，两个请求复用 |
| Native Hybrid keys | 同一示例接 `-- --hybrid`，显式 key P 与 partitioned QP 替代 radix key 后端 |
| Levels、自同构和秘密切换 | [leveled_coefficients](examples/leveled_coefficients.rs)：multiply/square、X→X⁵、Alice→Bob switching 和两次 drop |
| 明文子环 n<N | [subring_slots](examples/subring_slots.rs)：embed/extract、full-N secret/ciphertext 和空闲 slots 归零 |
| 加密 slots 运算 | [leveled_slots](examples/leveled_slots.rs)：子环中的 multiply/square、row rotation/swap、秘密切换和两次 drop |
| 临时 working basis | [working_basis](examples/working_basis.rs)：保持外部 level0 的普通三层 square 认证链；`--radix` 选择 radix keys |
| 借用已有秘密 | [explicit_coefficients](examples/explicit_coefficients.rs)：`BfvSecretKeyContext::try_new(&key,&context)` 和显式、会擦除的恢复 scratch |
| Raw GLWE 互操作 | [hybrid_rns_key_switch](examples/hybrid_rns_key_switch.rs)：为 raw switching/GGSW 消费者显式转换 phase |

```sh
cargo run -p primus_bfv --example ciphertext_multiplication
cargo run -p primus_bfv --example ciphertext_multiplication -- --hybrid
cargo run -p primus_bfv --example leveled_slots --features batching
```

Role-key operation 接 `(&context,&key)` 并从 key 推导 level；建钥、线性求值、
prime drop 仍显式选择实际 level；普通恢复从密文绑定推导 level。`try_with_levels(parameters,count)` 的数量
包含 level0；level l 移除最后 l 个 primes。每个使用的 level 都须生成对应 key。
`row_rotation_key` 的正步数在每行内左移，负步数右移；`row_swap_key` 交换两行。
一般多项式替换继续使用 `automorphism_key`。

多个角色可以一次准备 `context.radix_key_parameters(level,config)` 或
`context.hybrid_key_parameters(level,decomposition_count,&key_p)`，共享其 `Arc`。
共享数值 metadata 本身不证明外部导入的 secret 或变换来源。Key P 将求值密钥模数扩大到 QP，
须有独立误差/安全预算，与 BFV 乘法的 computation-only P 分开。
精确契约见 [Native Hybrid 指南](../../guides/development/native-hybrid-keys.md)（English）。

## 数值与所有权契约

加密接受恰好 N 个 `[0,t)` 内的 canonical 值。Unsigned 将 m 提升为 m；centered
采用 `[-floor(t/2),ceil(t/2))`；恢复返回 canonical 系数。明文加法恰乘一次 delta，
明文乘法采用未缩放 lift。由于 `delta*t` 未必等于 Q，模 t 归约带来的 encoding drift
也属于完整误差预算。

`BfvMultiplication` 组合 scale-and-round 与 native relinearization，返回一阶密文。
默认 `Exact` 用 computation P>NQ 保留整数 tensor。显式 `HpsPOverQ` 使用非对称
prescaling、自有的 P>2·#Q 条件和残差；选择 Hybrid key 不会自动选择 HPS。
[求值契约](../../guides/development/bfv-evaluation.md)（English）维护这些算法、
截断 radix residual、精确 rounded prime drop 和误差推导。
需要显式已缩放 quadratic 中间值时，继续使用 `BfvMultiplier` / `BfvRelinearizer`。
[Working-basis 契约](../../guides/development/bfv-working-basis.md)覆盖 depth 1～8 的普通
binary multiplication 族：用 `BfvLeveledRequest::create_context` 生成数值 context，
再由 `BfvLeveledParameters::try_new` 完整准入目标深度；已有 context 可直接提交自选
prime 链。预算基于真实 sampler 的公开 hard support，账本公开公钥误差、working HPS、
rounding、key 残差、fixed-Delta 漂移和剩余容量。独立 `security_inputs()` 计入实际
Hybrid QP 域，状态仍为 `NotEvaluated`；正确性准入不建立安全等级。
Collective 或 raw SSLE 需要另外计入完整误差。完整流程与独立离线筛查见
[参数与安全参考指南](../../guides/development/ordinary-parameter-budgets.md)。

Codec 只在恢复界内精确，不是任意 phase 的精确舍入 oracle。
`try_coefficients` 选择 gamma=2⁶¹−1 并要求 t<gamma；`try_new` 显式选择 gamma，
`try_with_error_distribution` 选择 error law。构造器检查充分的 fresh private recovery，
不证明公钥/求值恢复或安全级别。须计入公钥 noise、delta drift、求值、keyswitch residual
及每次 drop。自选 Q/P 必须确实是适用素数；支持 NTT roots 不等于证明素性。
优化后端要求 q_i<2⁶²。

Collective plan 借用各方 `DcrtGlweSecretKey<u64>`，要求精确 CBD1/CBD21 分布。
外围协议负责 roster/session/role 认证及实际 NTT/secret provenance；数量和分布 metadata
不能证明这些来源。两轮私有 state 采用消费式语义并擦除。
Fresh lookup 独立使用 `BfvFreshLookupKey` 与 `BfvRawQuadraticAggregate`，只执行一次
**unscaled** relin，不走普通 BFV scale-and-round；其 noise/ephemeral 必须独立于
selector 输入，包括间接 seed 依赖。`partial_phase_to` 只写 c1*s_i，发布前仍须由协议
消耗授权并加入完整隐私 flood。详见 [collective/lookup 契约](../../guides/development/native-hybrid-keys.md#collective-roles-and-fresh-lookup)（English）。

Raw GLWE 的 phase 为 b−a*s；显式 bridge 将 `[c0,c1]` 映射到 `[a=−c1,b=c0]`
并反向恢复，不执行 NTT。高级 CRT 输入保留两种不同语义：
`encrypt_plaintext_lift_crt_to` 对未缩放 lift 恰乘一次 delta；
`encrypt_encoded_crt_to` 接受已缩放 phase。二者均按 modulus-major Q 排列。
符号与表示细节见 [RNS phase 约定](../../guides/development/rns-phase-conventions.md)（English）
和各方法的 rustdoc。

## 资源与 features

Context 拥有 samplers/codecs 和不可变 Q tables；配对 context 可通过 `shared_table()` /
`try_with_table` 共享实际 table，仍检查 N/ordered Q。Client 拥有唯一变换域秘密和恢复
scratch；低层恢复借前缀。Prepared operation 借 context/key 并自持 mutable scratch，
并行请求各持独立 operation owner。Prepared `*_to` / `*_assign` 不分配临时存储。
秘密、ephemeral 和恢复 scratch 在 drop 时擦除。`into_secret_key` 消费 client，供下一
checked owner handoff 使用，不克隆秘密 share。

公开 coefficient 输入在 RNG 或写出前检查。Context 创建的密文及其 clone/view 保留
本地 context 与 level；prepared key 必须来自同一 context，已绑定的错 context/level
输入和输出在写前拒绝。`client.decrypt(&ciphertext)` 直接使用该绑定，但它不证明实际
secret 关系，也不认证通过 `AsMut` 改写的 residues。显式 `from_raw` / `zero_raw` 容器与
`decrypt_at_level` / `decrypt_at_level_to` 保留高级互操作的调用方合同。
`context.try_bind_ciphertext(raw,level)` 一次检查存储与规范性，实际变换和 secret 来源
仍由调用方保证。详见[context、level 与 raw 互操作](../../guides/development/scheme-context-binding.md)。
每个方法的准确输入、scratch 与 partial-write 契约以其 rustdoc 为准。

默认 features 为空。`batching` 启用共享 slot 编码；`simd` 转发共享 nightly 后端。
运行时 NTT intrinsic 分派独立于此 feature，关闭 `simd` 不表示强制 scalar NTT。
见 [feature 边界](../../guides/development/testing.md#features-与独立消费者)。

`parallel` 启用已接入的建钥与 gadget-product 路径中的有界 DCRT prefix 正逆 NTT
调度。每次 prefix 的 N≥4096 且至少两条 limb 时使用至多4个连续任务；总线程数须由
`RAYON_NUM_THREADS` 或 `ThreadPool::install` 限制。默认关闭，此 NTT 路径保持串行
且不初始化 pool；随机采样保持串行。

## 验证入口

```sh
cargo check -p primus_bfv --all-targets --features batching
cargo test -p primus_bfv --lib --tests --features batching
cargo clippy -p primus_bfv --all-targets --features batching -- -D warnings
```

测试保留独立 DFT/schoolbook/整数舍入 oracle，以及绑定、恢复、dirty scratch、擦除和
分配边界。Crate-local bench 测明确的 prepared 工作负载，setup 在计时外。
历史来源和工作负载限制见 [性能报告](../../guides/performance/bfv-multiplication.md)（English）。

## 公共对象持久化

`BfvContext::to_public_bytes()` 与 `from_public_bytes(bytes, limits)` 保存完整公共参数并重建新的本地 context；其 `export_*` / `import_*` 方法支持原生密文、公钥，以及 typed relinearization、switching、automorphism key，保留 Radix 或 Hybrid 的实际 Q/P 元数据。部署时设置 `PublicObjectLimits`；接收方在接受 owned 数据前检查版本、角色、完整几何、canonical residues 和实际 NTT 表示。BFV 保持独立的缩放和 decoder 参数。

不保存 secret 或本地绑定指针。上层须认证公共对象及其实际 source/target 身份和预算声明；结构校验不证明诚实建钥或实际 secret 关系。多次独立 key 导入可能重复准备 numerical metadata/P 表，本接口没有隐式 key cache。

完整契约见[公共对象持久化](../../guides/development/public-storage.md)及[BGV public-worker 示例](../primus_bgv/examples/public_worker.rs)：client secret 留在本地，worker 只处理公共字节容器。这些容器不向在线协议的逐轮 payload 添加 header。
