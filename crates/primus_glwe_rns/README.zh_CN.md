# primus_glwe_rns

[English](README.md) | 简体中文

有序 RNS 基上的 GLWE 加密与求值，分别使用 CRT 系数和 DCRT NTT 值。Raw 密文按
`[a_0,…,a_(k−1),b]` 存储，phase 为 `b−Σa_i*s_i`。本 crate 提供无 codec 的 phase
加密、gadget 乘法、自同构、trace、展开和密钥切换。普通系数/slots 消息使用
[BFV](../primus_bfv/README.zh_CN.md) 或 [BGV](../primus_bgv/README.zh_CN.md)。
Workspace API 和数值契约仍处于实验阶段。

## 无 codec 的 raw 流程

Raw 加密接受已经编码的 phase，不引入明文模数、BFV delta 或 decoder gamma。
从以下独立示例开始：

| 示例 | 新增概念 |
| --- | --- |
| [raw_encryption](examples/raw_encryption.rs) | 私钥 raw 加密、输出复用和 full/partial phase 提取 |
| [public_encryption](examples/public_encryption.rs) | 公钥绑定、多次 raw 加密和 ephemeral 擦除 |
| [gadget_encryption](examples/gadget_encryption.rs) | 显式分解参数下的进阶 monomial GGSW 加密 |

```sh
cargo run -p primus_glwe_rns --example raw_encryption
cargo run -p primus_glwe_rns --example public_encryption
cargo run -p primus_glwe_rns --example gadget_encryption
```

1. 准备有序 `RNSBase`、匹配的 `DcrtTable` 和 `RnsGlweSize`。
2. 通过 `CrtGlweEncryptionParameters::try_new` 选择 Gaussian，或使用
   `try_with_error_distribution` 显式选择分布。CBD1/CBD21 分别是精确的
   `CenteredBinomial { eta: 1 }` / `{ eta: 21 }`，不能用 Gaussian 近似替换。
3. 将有符号 `GlweSecretKey` 转为 DCRT，再绑定一次
   `key.try_bind_raw(&sampling,&base,&table)`。
4. 通过 `encrypt_encoded_crt_to` 或 `encrypt_zeros_to` 复用输出。私钥绑定借用
   现有资源，不分配 scratch。

## 公钥加密与预分配资源

用已检查的私钥绑定 `secret.public_key(&mut rng)` 生成 `DcrtGlwePublicKey`，再准备
`public.try_bind_raw(&sampling,&base,&table)`。可变 encryptor 借用公钥并拥有一份
ephemeral workspace，通过同一组 `_to` 方法复用调用方输出。Encoded CRT 输入在
component 原有的一次 NTT 前加入系数噪声，不增加缩放或变换。

导入 `zeroize::Zeroize` 后，`workspace_mut().zeroize()` 擦除 ephemeral 值并保留
内存；Drop 也会擦除。调用方密文输出独立保存。输出/workspace geometry 在采样或
写入前检查；canonical 输入与实际 key/NTT provenance 仍由调用方保证。

## 编码与表示

m 个模数下，raw 存储包含 `(k+1)*m*N` 个元素，顺序为
`[component][modulus][coefficient/evaluation]`。CRT 与 DCRT 形状相同，算术含义不同；
使用 checked sizes 与语义迭代器。见[密文布局](../primus_lattice/README.zh_CN.md#存储与布局)。

`key.phase_to(input,output,base.moduli())` 写出完整 DCRT phase；
`partial_phase_to` 只写出 `−Σa_i*s_i`。它们无需 sampler、transform table 或分配。
对 additive partial shares 求和后，b **只加入一次**。逆 NTT 和恢复为显式步骤；
这些原语不提供 opening 隐私、授权或重试规则。完整布局/模数顺序在写入前检查，
但数值相同不能证明实际 secret 或 NTT 身份。

BFV/BGV 原生 `[c0,c1]` 与 `c0+c1*s` phase 有独立方案语义。在真实 raw 消费边界
使用 BFV 的显式导入/导出；相同长度不允许直接把其缓冲区解释为 mask/body 密文。

## 参数组合

`CrtGlweEncryptionParameters` 拥有布局和采样预计算，不含 codec。每个噪声系数
只采样一次有符号整数，再一致提升到所有 RNS limbs；秘密和噪声支持须适用于每个
q_i。固定秘密重量作用于完整 kN key。构造不认证完整恢复/噪声界、NTT 可用性或安全等级。

`CrtGlevParameters::try_new(size,base,log_basis,levels)` 拥有 gadget base、分解及
weights，不携带 sampler 或 BFV 缩放。`try_from_parts` 接受独立准备的分解基，
检查其完整配对。Basis 须匹配 Q 和定宽 limbs，radix 严格小于每个 q_i。Gadget
加密/建钥单独接收采样参数，不同角色可选择独立误差规律。完整契约见
[采样参数](src/parameter/core.rs)与[gadget 参数](src/parameter/gadget.rs)。

## 求值资源

`try_bind_gadget(&gadget,&sampling,&table)` 返回私钥 `DcrtGlevEncryptor` 或公钥
`DcrtGgswEncryptor`。GLev 分开接受 CRT/DCRT 输入；GGSW monomial 加密施加 gadget
weights，`_to` 复用输出，分配式便利入口返回新结果。进阶示例只引入这项额外资源。
方案作者可通过 `encrypt_with_body_to` / `encrypt_with_components_to` 融合编码；
回调自行承担 canonical 范围、消息/噪声语义及开销，具体条件见方法契约。

Client 生成密钥；evaluator 借用 key、算术参数和 table，自持可变 scratch。构造器
在分配前检查完整数值配对，在线调用在写入前检查完整布局；实际 roots/order、秘密
身份及累计噪声仍由调用方保证。独立 worker 使用独立可变 evaluator。

| Evaluator | 输入 → 输出 | 准备资源 |
| --- | --- | --- |
| `CrtGlweAutoEvaluator` / `DcrtGlweAutoEvaluator` | 原秘密下的 CRT / DCRT | 自同构 key、gadget 和实际 table |
| `DcrtGlweKeySwitchEvaluator` | CRT Q → DCRT Q | `try_new(&key,&gadget,&table)` |
| `HybridRnsGlweKeySwitchEvaluator` | DCRT Q → DCRT Q | `try_new(&key,&hybrid_rns,&qp_table)` |

[Hybrid 建钥](src/key_switch/hybrid/generation.rs)检查输入秘密布局、两份秘密的
多项式长度、有序 Q 基和 QP 表，并检查误差采样器的幅度上界是否小于每个 QP 模数。
调用方须保证两份秘密的每个有符号系数的绝对值小于每个 QP 模数，导入密钥也须
满足此条件。提升范围见
[有符号秘密转换](src/secret_key/dcrt/conversion.rs)。
Evaluator 准备时检查有序 QP 基及其分区。ModUp 和 ModDown 顺序执行，因此转换
工作区取两者所需容量的较大值。其他同时活跃的缓冲区保持独立。数值契约见
[Hybrid RNS](../primus_rns/README.zh_CN.md#hybrid-rns)。

## Trace 与系数展开

Prepared evaluator 保留输入，覆盖调用方输出及 scratch。下列目标消息省略求值误差：

| 操作 | 目标消息 |
| --- | --- |
| CRT/DCRT `trace_to` | 常数 `N*m[0]` |
| DCRT reverse `trace_to` | 常数 `m[0]` |
| `expand_coefficients_to` | N 个输出，常数 `m[j]` |
| `expand_partial_coefficients_to` | 二次幂数量 d；`Σ_k m[j+k*d]X^(k*d)` |
| `expand_supported_coefficients_to` | 任意数量 k；明文次数 < k 时为常数 `m[j]` |

Reverse trace 是**模 Q 除2**，不是舍入或 modulus switch；后续 switching error
不一定只留在常数项。Partial 展开保留对应类中的高位明文系数；supported 展开则
需要调用方保证次数 < k，无法从密文检查。它按 `next_power_of_two(k)^−1 mod Q`
归一化，使用 k−1 次自同构，并加倍已是 scalar 叶子的现有误差；操作数不认证噪声或
安全界。完整条件见[reverse trace](src/dcrt/rev_trace.rs)、
[CRT 展开](src/crt/expand_coeff/evaluator.rs)和[DCRT 展开](src/dcrt/expand_coeff/evaluator.rs)。

并行展开使用正的 `worker_count` scratch 预算和调用方 Rayon pool，不创建内部pool。
预算不必等于线程数；写入前检查完整输入/输出 geometry。

## 普通 RLWE 参数准备

`rlwe_parameters` 提供冷构造时的自选 u64 素数验证和有界 NTT 素数搜索，
可额外要求 `q ≡ 1 (mod t)`。验证不同素数、`q < 2^62` 和 `2N | q-1`；
明文条件和误差预算仍由 BFV/BGV 负责。

`security_input` 为外部审查记录每个实际含秘密的 Q 或 Hybrid QP 域、精确乘积
及真实采样分布。它直接借用已准备的 rank-one 采样参数，不将分布字段拆开后重建
Gaussian 表。报告的 basis 可异于原采样 basis；该诊断不建立 context/key 绑定。
结果始终为 `NotEvaluated`：该函数不运行安全估算器，
也没有证明所请求的128位目标。BFV 计算用 tensor/HPS 素数不计入密钥曝光。
保留的顶层 Q 公开材料和各 working-basis 密钥需要分别列出；drop 不会撤销已有
曝光。环行的独立性、联合材料和 circular/KDM 假设仍需审查。

## 基准

[原始相位基准](benches/raw_phase.rs)分别测量自同构、普通与反向 trace，以及串行与
双 worker 系数展开。各操作使用同一份未缩放原始相位密文的 CRT 或 DCRT 表示。
Criterion 筛选单个操作时，准备仍在计时之外。

```sh
cargo bench -p primus_glwe_rns --bench raw_phase
```

## Feature 与进一步阅读

默认 features 为空；已启用所需 RNS 依赖，无需另设 `rns` 开关。`simd` 转发 nightly
SIMD feature。Runtime NTT intrinsic dispatch 独立于此 flag，关闭它不表示强制 scalar NTT。

`parallel` 启用共享 GLev/Hybrid 路径中的有界 DCRT prefix 正逆 NTT 调度。每次
prefix 的 N≥4096 且至少两条 limb 时使用至多4个连续任务；总线程数须由
`RAYON_NUM_THREADS` 或 `ThreadPool::install` 限制。默认关闭，此 NTT 路径保持串行
且不初始化 pool；随机采样不并行。

[公开 API 源码](src/lib.rs) · [库使用导航](../../guides/development/README.zh_CN.md)
· [测试与 feature 边界](../../guides/development/testing.md)
