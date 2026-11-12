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
`public.try_bind_raw(&sampling,&base,&table)`。可变 encryptor 借用公钥并拥有临时工作区，`_to` 方法复用调用方输出。导入
`zeroize::Zeroize` 后，用 `workspace_mut().zeroize()` 擦除临时值并保留分配。
工作区在 drop 时也会擦除。已检查的布局及调用方负责的输入和表条件见
[公钥加密契约](src/public_key/encryption.rs)。

## 编码与表示

m 个模数下，raw 存储包含 `(k+1)*m*N` 个元素，顺序为
`[component][modulus][coefficient/evaluation]`。CRT 与 DCRT 形状相同，算术含义不同；
使用 checked sizes 与语义迭代器。见[密文布局](../primus_lattice/README.zh_CN.md#存储与布局)。

`key.phase_to(input,output,base.moduli())` 写出完整 DCRT phase；
`partial_phase_to` 只写出 `−Σa_i*s_i`。它们无需 sampler、transform table 或分配。
对 additive partial shares 求和后，b **只加入一次**。逆 NTT 和恢复为显式步骤；
这些原语不提供 opening 隐私、授权或重试规则。完整布局/模数顺序在写入前检查，
但数值相同不能证明实际 secret 或 NTT 身份。

[Phase 指南](../../guides/development/rns-phase-conventions.md)（English）说明
如何显式转换到 BFV 的 `[c0,c1]` 布局及 `c0+c1*s` 约定。

## 参数组合

[`CrtGlweEncryptionParameters`](src/parameter/core.rs) 拥有布局和采样预计算。
每个有符号误差系数只采样一次，再提升到所有 limb。秘密和噪声支持须适用于每个
`q_i`，固定重量针对完整的 `kN` 秘密。调用方需另行确认恢复界、NTT 表和安全参数。

[`CrtGlevParameters`](src/parameter/gadget.rs) 拥有有序 `Q` 基的 gadget 分解。
分解基须匹配 `Q` 的定宽 limb 数，radix 严格小于每个 `q_i`。单独绑定采样，
便于不同密钥角色选择各自的噪声规律。

## 求值资源

通过 `try_bind_gadget(&gadget,&sampling,&table)` 准备私钥
`DcrtGlevEncryptor` 或公钥 `DcrtGgswEncryptor`。GLev 分开接收 CRT 和 DCRT 输入。
[gadget 加密示例](examples/gadget_encryption.rs)展示如何复用 GGSW 单项式加密的输出。

Evaluator 借用不可变的密钥、参数和表，自持可变 scratch。求值前绑定完整有序基、
分解和表。每个 worker 使用各自的 evaluator。调用方保证根与求值顺序匹配、
秘密身份一致以及适用的误差预算。

| Evaluator | 输入 → 输出 | 准备资源 |
| --- | --- | --- |
| `CrtGlweAutoEvaluator` / `DcrtGlweAutoEvaluator` | 原秘密下的 CRT / DCRT | 自同构 key、gadget 和实际 table |
| `DcrtGlweKeySwitchEvaluator` | CRT Q → DCRT Q | `try_new(&key,&gadget,&table)` |
| `HybridRnsGlweKeySwitchEvaluator` | DCRT Q → DCRT Q | `try_new(&key,&hybrid_rns,&qp_table)` |

[Hybrid 建钥](src/key_switch/hybrid/generation.rs)检查输入秘密布局、两份秘密的
多项式长度、有序 Q 基和 QP 表，并检查误差采样器的幅度上界是否小于每个 QP 模数。
调用方须保证两份秘密的每个有符号系数的绝对值小于每个 QP 模数，导入密钥也须
满足此条件。参见[提升范围](src/secret_key/dcrt/conversion.rs)
和 [Hybrid RNS 契约](../primus_rns/README.zh_CN.md#hybrid-rns)。

## Trace 与系数展开

Prepared evaluator 保留输入，覆盖调用方输出及 scratch。下列目标消息省略求值误差：

| 操作 | 目标消息 |
| --- | --- |
| CRT/DCRT `trace_to` | 常数 `N*m[0]` |
| DCRT reverse `trace_to` | 常数 `m[0]` |
| `expand_coefficients_to` | N 个输出，常数 `m[j]` |
| `expand_partial_coefficients_to` | 二次幂数量 d；`Σ_k m[j+k*d]X^(k*d)` |
| `expand_supported_coefficients_to` | 任意数量 k；明文次数 < k 时为常数 `m[j]` |

Reverse trace 在模 Q 下除以二。其换钥误差可以出现在非常数项。
Supported 展开要求调用方保证明文次数小于请求的输出数。归一化和误差契约见
[reverse trace](src/dcrt/rev_trace.rs)、[CRT 展开](src/crt/expand_coeff/evaluator.rs)
和 [DCRT 展开](src/dcrt/expand_coeff/evaluator.rs)。并行展开使用调用方的 Rayon
线程池和正的 `worker_count` scratch 预算。

## 普通 RLWE 参数准备

[`rlwe_parameters`](src/rlwe_parameters.rs) 检查调用方提供的 u64 NTT 素数，
并提供有界的素数搜索。`security_input` 记录含秘密的域并返回 `NotEvaluated`。
清单范围及独立安全评估见[参数与安全指南](../../guides/development/ordinary-parameter-budgets.md)。

## 基准

参见[原始相位基准](benches/raw_phase.rs)。

```sh
cargo bench -p primus_glwe_rns --bench raw_phase
```

## Feature 与进一步阅读

默认 features 为空；已启用所需 RNS 依赖，无需另设 `rns` 开关。`simd` 转发 nightly
SIMD feature。Runtime NTT intrinsic dispatch 独立于此 flag，关闭它不表示强制 scalar NTT。

`parallel` 为 GLev 和 Hybrid 共享路径启用 [DCRT 前缀调度](../primus_ntt/src/dcrt/mod.rs)，
使用调用方的 Rayon 线程池。

[公开 API 源码](src/lib.rs) · [库使用导航](../../guides/development/README.zh_CN.md)
· [测试与 feature 边界](../../guides/development/testing.md)
