# primus_glwe_rns

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

有序 RNS 基上的 GLWE 加密与求值，分别使用 CRT 系数表示和 DCRT NTT 表示。提供无 codec 的 phase 加密、gadget 乘法、自同构、trace、展开与密钥切换。BFV 消息缩放、系数加密与恢复归属 [primus_bfv](../primus_bfv/README.zh_CN.md)。

## 无 codec 的 raw 流程

调用方自行定义 encoded phase 时使用 raw 加密，无需明文模数、BFV 尺度、辅助解码模数 gamma 或 gadget 基：

1. 准备有序 `RNSBase`、匹配的 `DcrtTable` 和 `RnsGlweSize`。
2. 构造 `CrtGlweEncryptionParameters`。`try_new` 选择 Gaussian 噪声；`try_with_error_distribution` 还接受 `primus_distr` 的精确 `ErrorDistribution::CenteredBinomial { eta }`。eta=1 是 CBD1，eta=21 是 CBD21；标准差相近的 Gaussian 是另一种分布。
3. 使用 `DcrtGlweDomain::try_new(&parameters, &base, &table)` 绑定资源，将有符号 `GlweSecretKey` 转为 DCRT，再调用一次 `key.try_bind_raw(&domain)`。
4. 通过返回的 `DcrtGlweRawSecretKeyContext` 复用调用方的密文及多项式输出。绑定只借用资源，不克隆密钥；raw 操作不分配 scratch。

| Raw context 方法 | 结果 |
| --- | --- |
| `encrypt_encoded_crt_to` | 将规范 CRT 系数直接加入系数噪声，DCRT 输出 phase 为 encoded 输入加噪声，不隐式缩放 |
| `encrypt_zeros_to` | 同一 DCRT 布局下的新鲜零加密 |
| `phase_to` | 完整 DCRT phase `b - sum(a_i*s_i)` |
| `partial_phase_to` | 不含 body b 的 DCRT contribution `-sum(a_i*s_i)` |

对 additive secret shares 求 partial phase 之和后，b **只加入一次**；也可由一方生成 full phase，其余方生成 partial phase。这里仅提供 raw 算术，opening 隐私噪声、允许公开的输出及一次性/重试规则由协议负责。Phase 输出仍在 NTT 域，逆变换和任何解码均由调用方显式执行。

Domain/key 绑定检查布局和有序模数。Raw 方法在写入或采样前拒绝不完整的缓冲区长度；规范剩余类、变换身份、实际 secret 身份和消息语义仍由调用方保证。[Raw 加密示例](examples/raw_encryption.rs) 展示完整的 u64 流程、存储复用及 body/share 关系：

```sh
cargo run -p primus_glwe_rns --example raw_encryption
```

方案实现可通过私钥 `encrypt_with_body_to` 或公钥 `encrypt_with_components_to`，将编码融合进已采样的系数噪声。回调在对应 component 唯一一次 NTT 前执行；公钥入口按 mask、body 顺序访问。原语自身不分配缓冲区；回调的开销、规范剩余类以及消息/噪声语义由调用方负责。普通 BFV 使用者直接使用 `primus_bfv`。

## BFV 消息流程

秩一 u64 BFV 参数、unsigned/centered 系数加密、未缩放 CRT 明文加密与解码，使用 [primus_bfv](../primus_bfv/README.zh_CN.md)。本 crate 的 raw 方法接收已编码 phase，不施加 BFV delta；gadget 消息则使用自己的分解权重。

## 公钥加密与预分配资源

使用无 codec 的采样参数生成一次 `DcrtGlwePublicKey`。下列绑定借用密钥，并各自准备一份拥有型 ephemeral 工作区；加密方法均接收 `&mut self`：

| 绑定 | Prepared encryptor | 输入 |
| --- | --- | --- |
| `public_key.try_bind_raw(&domain)` | `DcrtGlweRawPublicKeyEncryptor` | 已编码 CRT phase 或零，不隐式缩放 |
| `public_key.try_bind_gadget(&gadget_domain)` | `DcrtGgswEncryptor` | Monomial 系数剩余类和次数，施加 gadget 权重 |

通过 `encrypt_encoded_crt_to`、`encrypt_zeros_to` 或 `encrypt_monomial_ggsw_to` 复用调用方输出。Prepared `_to` 调用完整覆盖 DCRT 输出，不分配内存；便利方法 `encrypt_monomial_ggsw` 仅分配返回的结果。Encoded CRT phase 或 gadget monomial 与系数噪声融合，在该 component 原有的一次 NTT 前注入；这些输入不是 DCRT 多项式。

`workspace()` 提供保留 scratch 的布局；导入 `zeroize::Zeroize` 后，`workspace_mut().zeroize()` 可显式擦除 ephemeral 值并保留内存供复用，drop 也会擦除。否则最后的值一直保留到下次覆盖。调用方的密文输出独立于工作区，不由工作区清理擦除。输出、系数剩余类数量、次数和工作区形状的检查均在采样与写入前执行；规范剩余类和实际 key/NTT domain 仍由调用方保证。

[公钥加密示例](examples/public_encryption.rs) 组合 raw 和 gadget 模式，复用输出并显式擦除 scratch：

```sh
cargo run -p primus_glwe_rns --example public_encryption
```

## 编码与表示

Raw 加密直接接收规范 CRT 剩余类，不解释明文模数或施加消息缩放；phase 输出为 DCRT，逆变换和消息恢复均为显式操作。GLev 通过不同方法接收 CRT 或 DCRT 输入并施加 gadget 权重。

m 个模数下，普通密文包含 `(k+1)*m*N` 个元素，顺序为 `[component][modulus][coefficient/evaluation]`；gadget 在外层增加 row/level。CRT 与 DCRT 形状相同，算术含义不同。使用 `RnsGlweSize` / `RnsGadgetSize` 及语义迭代器，始终保持模数顺序。见[密文布局](../primus_lattice/README.zh_CN.md#存储与布局)。

## 参数组合

| 参数 | 用途 |
| --- | --- |
| `CrtGlweEncryptionParameters` | 布局、有序模数及采样器；无明文 codec |
| `DcrtGlweDomain` | 采样参数、有序 RNS 基及 DCRT table 的 checked codec-free 绑定 |
| `CrtGlevParameters` | 加密参数及乘积模数 Q 下的 gadget 分解；无 BFV 缩放 |

维数和环长度使用 `GlweDimension` 与 [PolyLength](../primus_shape/README.zh_CN.md#多项式长度)，分解使用 `DecompositionBaseLog` / `DecompositionLevelCount`，在参数、尺寸和表之间复用这些已验证值。固定秘密重量作用于完整 kN 个有符号系数，不是逐多项式或逐 RNS limb 应用。秘密和噪声幅度须小于每个 q_i。每个噪声系数只采样一次整数，再一致地提升到所有 RNS limbs。`CrtGlweEncryptionParametersError` 报告无 codec 的 domain/采样错误；BFV 参数和恢复错误归属 `primus_bfv`。

通过 [`CrtGlevParameters::try_from_parts`](src/parameter/gadget.rs) 绑定共享加密参数、有序基及匹配的分解基，无需 t 或 gamma。BFV 使用者可在方案 crate 通过 `BfvParameters::try_gadget_parameters` 派生这些参数。分解基须匹配 Q 及其定宽 limb 表示，radix 须严格小于每个 q_i。密钥角色需要不同噪声分布时，应分别准备加密参数。

Raw 参数构造建立布局和采样支持条件，不建立消息恢复界、NTT 可用性或安全等级。公钥加密及同态求值仍需完整操作的 phase error 界。

## 求值资源

Raw 私钥/公钥使用 `try_bind_raw(&domain)`。Gadget 使用 `DcrtGadgetDomain::try_new(&gadget, &table)`，再调用 `try_bind_gadget(&domain)`：私钥返回 `DcrtGlevEncryptor`，公钥返回 `DcrtGgswEncryptor`。GLev 的 `encrypt_crt_to` / `encrypt_dcrt_to` 接收系数 / NTT 消息并施加 gadget 权重；GGSW 的 `encrypt_monomial_ggsw` / `encrypt_monomial_ggsw_to` 分别分配 / 复用输出。

Client 生成公钥及求值密钥并交给 server。公钥和 key-switch 密钥生成使用无 codec 的 `encryption_parameters()`。从密钥及 domain 构造一次 evaluator，在线调用复用其自身 scratch。绑定检查资源布局、有序基及相应分解参数。Evaluator 和 prepared 公钥/gadget 加密方法在写入前检查完整输入输出长度；规范剩余类、NTT 根/顺序、秘密身份和足够的噪声余量仍由调用方保证。

使用 `DcrtGlweAutoKey::new(&gadget_domain, exponent, &key, &mut rng)` 准备自同构密钥，再绑定一次 `DcrtGlweAutoEvaluator::try_new(&auto_key, &gadget_domain)` 并复用输出。上方链接的示例展示 gadget 参数构造及 raw/公钥输出复用。

`CrtGlweAutoEvaluator` 使用系数密文，`DcrtGlweAutoEvaluator` 使用 NTT 密文，两者均返回原秘密下的结果。

| Key-switch evaluator | 输入 → 输出 | Domain |
| --- | --- | --- |
| `DcrtGlweKeySwitchEvaluator` | CRT Q → DCRT Q | 有序 Q 上的 `DcrtGadgetDomain`，gadget 布局及 radix 匹配 |
| `HybridRnsGlweKeySwitchEvaluator` | DCRT Q → DCRT Q | 有序 QP 上的 `HybridRnsKeySwitchDomain`，N、Q/P 分界及分区宽度匹配 |

两者均提供 `try_new(&key, &domain)`，在线调用为 `key_switch_to(&input, &mut output)`。Hybrid 密钥生成从输入加密参数取得密钥噪声，检查其支持范围是否适用于每个 QP 模数；两个秘密的幅度也必须小于每个 QP 模数。分区及 ModUp/ModDown 契约见 [`primus_rns`](../primus_rns/README.zh_CN.md#hybrid-rns)。

## Trace 与系数展开

这些 evaluator 借用密钥和 gadget domain，并拥有可复用 scratch。输入保持不变，输出及 scratch 被覆盖。下表目标消息省略求值误差。

| Evaluator 及方法 | 目标消息 |
| --- | --- |
| `CrtGlweTraceEvaluator` / `DcrtGlweTraceEvaluator`，`trace_to` | 常数 `N*m[0]` |
| `DcrtGlweRevTraceEvaluator`，`trace_to` | 常数 `m[0]` |
| CRT/DCRT 的 `expand_coefficients_to` | 恰好 N 个输出，第 j 个目标为常数 `m[j]` |
| CRT/DCRT 的 `expand_partial_coefficients_to` | 数量 d 为 `1..=N` 内二次幂，输出 j 目标为 `sum_k m[j+k*d] * X^(k*d)` |
| CRT/DCRT 的 `expand_supported_coefficients_to` | 任意数量 k 在 `1..=N` 内；明文次数小于 k 时，输出 j 目标为常数 `m[j]` |

Reverse trace 在每次自同构及相加前乘 `2^-1 mod q_i`，保持 Q 和环长度；这是模除法，不是 modulus switch 或舍入减半。完整序列将输入消息和输入误差投影到常数项，但较晚引入的 key-switch 误差可能留在非常数位置。不能从无舍入推出 native-torus 方差界，详见[相位与误差契约](src/dcrt/rev_trace.rs)。

展开没有额外的 count 倍数。Partial 展开将较高的**明文**系数保留在相应剩余类中，Relect 的 block-factor accumulator 需要此行为。Supported 展开则要求协议或调用方保证明文次数小于 k，无法在运行时从密文检查该条件。它按 `next_power_of_two(k)^-1 mod Q` 归一化，只计算 k−1 次自同构；已是 scalar 的叶子直接加倍，避免求值 padding 分支；已有 phase error 也随之加倍，操作次数不代表噪声或安全界。密文和噪声尾部无需为零，环长度仍为 N。完整布局与表示条件见 [CRT](src/crt/expand_coeff/evaluator.rs) 和 [DCRT](src/dcrt/expand_coeff/evaluator.rs) evaluator。

串行展开使用 `*GlweExpandCoeffEvaluator::new(&key, &domain)`，预分配 scratch 预算使用 `*GlweExpandCoeffParallelEvaluator::new(&key, &domain, worker_count)`。串行求值只需一份工作区，并行求值保留 `worker_count` 份工作区；重复调用复用算术 scratch。

并行调用使用调用方 Rayon pool，每层最多分成 `worker_count` 个占用 scratch 的作业。此正数预算可小于或大于 pool 线程数，不创建内部线程池。求值前初始化调用方 pool，调用时可变借用 evaluator。完整输入/输出长度和数量均在写入前检查；具体数值及资源契约见 evaluator 方法。

## Feature 与进一步阅读

默认 features 为空，`simd` 向算术依赖转发 nightly SIMD。本 crate 已启用所需的 RNS features，无需另设 `rns` 开关。

[公开 API 源码](src/lib.rs) · [RNS 基与转换](../primus_rns/README.zh_CN.md) · [库使用导航](../../guides/development/README.zh_CN.md) · [测试指南](../../guides/development/testing.md)
