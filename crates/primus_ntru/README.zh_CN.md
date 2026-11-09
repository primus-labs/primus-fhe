# primus_ntru

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。尚不提供推荐安全参数。

在 `Z_q[X]/(X^N + 1)` 上提供单多项式私钥 NTRU 加密与求值。NTT 使用显式域模数。

## 快速开始

下面使用 u64 和 NTT 展示普通消息与 encoded/phase 两条路径。调用方直接依赖 `primus_ntru`（启用 `ntt`）、`primus_ntt`、`primus_poly`、`primus_modulus`、`primus_encoding` 和 `rand`。N=32 仅用于简短的功能示例，不是安全参数。

```rust
use primus_encoding::PlaintextEmbedding;
use primus_modulus::BarrettModulus;
use primus_ntru::{NtruParameters, NttNtruSecretKey, SecretKeyDistr};
use primus_ntt::{NttTable, U64NttTable};
use primus_poly::Polynomial;
use primus_shape::PolyLength;

let poly_length = PolyLength::new(32);
let modulus = BarrettModulus::new(132_120_577u64);
let table = U64NttTable::new(poly_length, modulus).unwrap();
let params = NtruParameters::new(poly_length, 16, modulus, SecretKeyDistr::SparseTernary, 0.7);
let mut rng = rand::rng();
let (_coeff_secret, secret) =
    NttNtruSecretKey::generate_pair(params.encryption_parameters(), &table, &mut rng).unwrap();
let message = Polynomial::new(vec![3u64; poly_length.get()]);
let embedding = PlaintextEmbedding::Unsigned;

// 普通消息：适配层使用参数中的 codec。
let mut ciphertext = secret.encrypt_message(&message, &params, embedding, &table, &mut rng);
assert_eq!(
    secret.decrypt_message(&ciphertext, &params, &table),
    message
);

// 已编码输入和提取出的 phase 都是系数多项式。
let codec = params.plaintext_codec();
let mut encoded = Polynomial::new(vec![0; poly_length.get()]);
codec.encode_slice_to(message.as_ref(), encoded.as_mut(), embedding);
secret.encrypt_encoded_to(
    &encoded,
    &mut ciphertext,
    params.encryption_parameters(),
    &table,
    &mut rng,
);
let mut phase = Polynomial::new(vec![0; poly_length.get()]);
secret.decrypt_phase_to(&ciphertext, &mut phase, modulus, &table);
let mut decoded = vec![0; poly_length.get()];
codec.decode_slice_to(phase.as_ref(), &mut decoded);
assert_eq!(decoded, message.as_ref());
```

用 `encrypt_message_to` 复用密文存储，无需单独的 encoded 多项式。重复请求保留参数、表、密钥和输出。

## 密文语义

设 `f` 为可逆私钥，`mu` 为编码消息，`g_l` 为 gadget scalar。下列相位省略应用层的明文编码：

| 类型 | 系数行 `c_l` 的相位 |
| --- | --- |
| NTRU | `f*c = mu + e` |
| 消息 `m` 的 NLev | `f*c_l = g_l*m + e_l` |
| 消息 `m` 的 NGSW | `f*c_l = g_l*f*m + e_l` |

NLev 和 NGSW 存储的行数相同，角色却不同。`NLev[1]` 可通过外积把公开系数多项式提升为加密的 NTRU；`NGSW[1]` 保留已有密文的消息。将消息复制到 `c` 一般不能构成 NTRU 平凡加密。

## 参数与密钥

| 参数 | 用途 |
| --- | --- |
| `NtruParameters` | 带 `ScaledCodec` 的普通加解密 |
| `NtruEncryptionParameters` | 密钥生成、encoded/零加密所需的环和采样器；无 codec |
| `NlevParameters` | 加密参数及 gadget 分解；无明文 codec |

普通消息使用 `NtruParameters::try_new`。已有普通参数时，`NlevParameters::try_with_ntru_params(&ntru_params, decomposition)` 接收 `DecompositionConfig`，派生同一环上的 gadget 参数并复用已准备的采样器；`try_with_basis` 接收已准备的分解基。仅使用 gadget 的构造方式见 [NlevParameters](src/parameter/gadget.rs)。

[PolyLength](../primus_shape/README.zh_CN.md#多项式长度) 构造一次，供参数、表和工作区复用。固定秘密重量不得超过 N。参数检查覆盖编码及采样，不证明秘密可逆、变换可用或噪声/安全预算成立。

将 `encryption_parameters()` 传给 `NttNtruSecretKey::generate_pair`。返回的有符号系数私钥用于生成求值密钥，变换私钥用于加密和相位提取。`try_from_coeff_secret_key` 转换已有私钥，也可能拒绝它；NTT 导入要求有符号系数幅度小于 q。后续操作须保持构造时的表示，相同 q/N 不能证明 NTT 根、求值顺序或秘密身份相同。

NTT 生成拒绝零点值。有界拒绝采样可能失败，重试次数及求逆例程不承诺常数时间。候选搜索失败返回 `KeyGenerationExhausted`。返回秘密服从候选分布**在后端接受条件下的条件分布**，`distr()` 记录候选分布。

一般 NTRU 支持非 binary 环秘密。NTRU TFHE 使用独立外部 LWE 秘密作为 binary/ternary 盲旋转控制，不要求环秘密为补零 binary。

私钥及私有加密、生成、解密工作区析构时擦除自身缓冲区。显式清零后应丢弃私钥。内置 FFT 后端析构时擦除 scratch，长寿命 engine 可使用 `FftEngine::zeroize_workspace()`。调用方持有的明文和相位输出另行管理生命周期。

[自同构示例](examples/automorphism.rs) 展示密钥生成，以及原秘密下可复用的 NTT 求值：

```sh
cargo run -p primus_ntru --example automorphism --features ntt
```

## 加密与解密

| 方法 | 输入或结果 |
| --- | --- |
| `encrypt_message` / `encrypt_message_to` | `[0, t)` 中的消息和显式 `PlaintextEmbedding`；分配 / 覆盖变换域密文 |
| `encrypt_encoded_to` / `encrypt_zeros_to` | 编码系数 / 零多项式到变换域密文，不进行明文缩放 |
| `decrypt_phase_to` | 系数域 `f*c`，不解码 |
| `decrypt_message` / `decrypt_message_to` | 解码后的系数多项式；分配 / 覆盖输出 |

消息方法使用 `NtruParameters`，encoded/零加密使用 `NtruEncryptionParameters`。`Unsigned` 与 `Centered` 均接收 `[0, t)` 中的规范剩余类，centered 的 `t-1` 表示 `-1`；两者使用相同解码器。解码结果保留系数类型 `T`。

NTT 私钥运算不需要工作区。已编码 NTT 输入须为模 q 的规范系数。密钥、参数、表和输出须匹配；非法明文可能在部分写入或消耗随机数后失败。精确缓冲区及失败契约见[私钥方法](src/secret_key)。

做[相位误差诊断](../primus_encoding/README.zh_CN.md#相位误差诊断)时，用实际 codec 和 embedding 编码**预期消息**，再与相位比较。先解码再重新编码不能提供独立参考。

## Gadget 与求值原语

| 运算 | 输入与输出 |
| --- | --- |
| `encrypt_nlev_to` / `encrypt_ngsw_to` | 环多项式到变换域 gadget 行，不做明文 codec 缩放 |
| `encrypt_nlev_constant_to` | 环常数到变换域 NLev |
| `encrypt_ngsw_signed_constant_batch_to` | 有符号常数到连续的变换域 NGSW |
| `NttNtruKeySwitchingKey` | 输入秘密下的系数 NTRU 到输出秘密下的系数 NTRU |
| 自同构 `apply_to` | 原秘密下，应用 `X -> X^d` 后的系数 NTRU |
| 自同构 `apply_ntt_to` | 对应的变换域输入输出 |

求值密钥持有分解基，匹配的工作区构造一次即可复用。自同构要求 `d` 为 `[1, 2N)` 中的奇数。NLev 可以逐行应用标量自同构，但对 NGSW 逐行应用**不能**保持其消息/密钥关系。

`NttNlev::lift_monomial_to` 融合公开多项式提升与首次 binary/ternary 旋转。传入 NLev[1]、正控制 NLev 位和可选的负控制 NLev 位，指数为零时仍须提升。后续 ternary `cmux_ternary_monomial_to` 使用互斥的正/负 NGSW 控制位。指数应已量化到 `0..2N`。复用 `NttNtruCmuxWorkspace::new(poly_length, levels)`。

样本提取、外积、lift 和 CMUX 见 [`primus_lattice`](../primus_lattice/README.zh_CN.md)。PBS、ManyLUT 与 CBS 流程见 [NTRU NTT 后端](../primus_tfhe_ntru_ntt/README.zh_CN.md)。

## 独立 LWE 返回

`NtruLweKeySwitchingKey::generate(f, Q, s, &parameters, rng)` 准备从 Q 下 NTRU 秘密 f 到 q 下独立 `LweSecretKey` s 的返回密钥。用 `primus_lwe::LweKeySwitchingParameters::try_new(output, basis)` 组合无 codec 的目标 LWE 加密状态与 q 下的分解基；源模数 Q 仍独立传入。输出维数可不同于 N，s 无需扩展为可逆 NTRU 秘密；f 每个有符号系数的幅度须小于显式 q。

输入为系数域 NTRU 密文，变换域输出须先恢复为系数。用 `LweReturnEvaluator::new(&key, q_modulus)` 绑定密钥与目标模数，再按需求分配并复用下列 scratch。所有路径覆盖输出，无在线分配，也无需 变换依赖。

| 请求结果 | Evaluator 方法 | 工作区构造方法 |
| --- | --- | --- |
| 一个系数 | `return_at_to` | `new_scalar_workspace()` |
| 同一 NTRU 的多个系数 | `return_many_at_to` / `return_prefix_to` | `new_batch_workspace()` |
| 连续产生的不同 NTRU 的系数 | 工作区 `begin_batch`、evaluator `append_at`，再 `return_batch_to` | `new_batch_workspace()` |

共享输入返回复用一次 Q→q 转换。`return_many_at_to` 保留任意索引顺序与重复项，`return_prefix_to` 选择 `0..outputs.len()`。空请求不写入，单项请求采用标量路径。

`LweReturnBatchWorkspace` 跟踪当前流的有效前缀。每次追加后不保留输入借用；提交数量须恰好等于追加数量，且不超过 `batch_capacity()`。共享输入返回或换用其他绑定前，须结束或取消当前流。工作区状态不证明密钥身份：追加及提交须使用相同的实际秘密与 Q/q。状态及失败契约见 [LweReturnEvaluator](src/key_switch/lwe/evaluator.rs)。中间 slot 仅供内部使用，调用方不能提交未准备的样本。

运算先逐系数计算 `c' = round(q*c/Q) mod q`（最近舍入，半点向上），再在 f 下提取并于 q 下 key switch。提取的相位为 `b-<a,f> = (f*c')[index]`。**舍入先于提取中的取负**，交换次序会改变半点结果。Mask 布局见 [LweReturnEvaluator](src/key_switch/lwe/evaluator.rs)。

Q 和 q 均可为原生或显式模数，也可以相同。返回保留系数类型（u32→u32 或 u64→u64），缩小 q 不改变字宽。输入须为 Q 下规范剩余类。噪声预算包含 f 加权的舍入、秘密加权的分解误差和 LWE 密钥噪声，以及已有 NTRU/FFT 误差。将 Q 下编码消息缩放到 q，一般不等于直接在 q 下重新编码。

## Trace、投影与展开

`NttNtruTraceKey` 操作原秘密下的系数密文。下表中 `M` 是输入消息，目标消息省略求值噪声。

| 方法 | 目标消息 |
| --- | --- |
| `apply_to` / `apply_reverse_to` | 常数 `N*M[0]` / `M[0]` |
| `apply_partial_to(input, r, ...)` | `d * sum_j M[j*d] X^(j*d)`，其中 `d=N/r` |
| `apply_reverse_partial_to(input, r, ...)` | `sum_j M[j*d] X^(j*d)` |
| `project_coefficient_to` / `project_coefficients_to` | 常数 `M[index]` / 按选择顺序排列的常数 |
| `project_prefix_coefficients_to(input, count, ...)` | 前 `count` 个系数各自作为常数；无需零尾部 |
| `expand_coefficients_to` | 全部 N 个系数各自作为常数 |
| `expand_partial_coefficients_to(input, count, ...)` | 前 `count` 个常数，要求消息尾部为零 |

部分 trace 接收 `1..=N` 中的二次幂 r；r=N 复制输入，r=1 为完整 trace。Reverse trace 在每次自同构及相加前归一化，采用 `2^-1 mod q`。误差项见 [trace 方法](src/trace)。

投影接受任意索引，包括重复索引和空选择；前缀投影接受 `0..=N` 中任意数量。每个选中系数都需要一次完整 reverse trace，数量为一也如此。部分展开要求数量为 `1..=N` 中的二次幂，一时复制输入，N 时为完整展开。它只归一化一次，误差行为与投影不同。

部分展开仅在**消息**的 `count..N` 系数为零时产生常数；否则输出 i 的目标是 `sum_j M[i+j*count] X^(j*count)`。密文和噪声尾部无需为零，所有输出仍保持环长度 N。

## 同一秘密下的 scheme switching

`NttNtruSchemeSwitchKey` 将系数 `NLev_f[m]` 转为变换域 `NGSW_f[m]`。`key_basis` 控制分解，独立的 `output_basis` 指定输入输出 gadget scalar 和层数。输入必须已使用该输出基，长度匹配不足以证明这一点。复用匹配的外积工作区。

求值材料为 `NGSW_f[f]`。输入误差乘 f，分解误差乘 f²，密钥误差也参与结果。公开该秘密相关材料需要有依据的 key-dependent-message/circular-security 假设和合适参数；功能正确性不提供安全证明或 CBS 参数推荐。m 为 bit 时输出可控制 CMUX，完整相位契约见 [scheme switching](src/scheme_switch)。

对于只需要 NGSW 输出的打包系数，[`NttNtruProjectionKey`](src/scheme_switch/projection.rs) 显式接收 `NtruProjectionMethod`：`Separate`（枚举默认值）、`FusedLastStage`、`FusedLastThreeStages` 或 `PairedTrace`。最后一种两两合并 reverse trace 阶段，将末两层或三层与 SS 融合。`project_to` 接受一般非零消息尾部；用 `scratch_len()` 分配可复用缓冲（依次为 2N、2N、8N、5N/8N；paired 的大小取决于 log₂N 的偶/奇性）。仅生成所选策略的融合材料。融合改变分解残差与密钥误差，切换策略需要重新评估噪声预算。NLev 或双输出可以借用其中的普通 trace/SS 密钥。

## Features

默认 features 为空，NTRU→LWE 返回无需变换后端。`ntt` 启用 NTT 运算。`simd` 只转发给已启用的算术依赖，不启用变换后端。

测试、示例和基准声明 `required-features`；缺少时 Cargo 会跳过整个 target。按相应运行命令选择 features。

## 更多资料

逐方法契约见 [API 源码](src)，负载与运行命令见[基准指南](benches/README.zh_CN.md)，验证命令见 workspace [测试指南](../../guides/development/testing.md)。

## 许可证

可选择 [Apache-2.0](../../LICENSE-APACHE-2.0) 或 [MIT](../../LICENSE-MIT) 许可证。
