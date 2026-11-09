# primus_tfhe_ntru

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

NTRU-TFHE 的参数及外部 LWE 客户端。Context、求值密钥、evaluator 和完整示例见 [NTT](../primus_tfhe_ntru_ntt/README.zh_CN.md) 后端，操作和编码选择见[公共指南](../primus_tfhe/README.zh_CN.md)。

## 实验配套参数

从具体后端的 `experimental::*_U64` 操作配置开始。这些教学参数未评估安全性或失败概率，详见[参数条件](../../guides/development/tfhe-parameters.md#scope-of-paired-parameter-entries)。

| 配置 | 用途 |
| --- | --- |
| `PbsConfig` | PBS、ManyLUT 和 MVB：外部 LWE、accumulator/BSK、BR 算法、必需返回 KS 及消息域 |
| `CbsConfig { pbs, gadget, projection }` | 相同 PBS 域，加上 CBS output、trace 和 scheme-switch 分解；也用于 one-hot |

使用后端 `TfheContext::try_from_pbs_config` / `try_from_cbs_config`。显式准备参数用 `PbsParameters::try_from_config` 或 `CbsParameters::try_from_config(cbs_config)`，`CbsParameters::try_with_config(pbs, gadget, projection)` 复用已有 PBS 参数。`try_with_circuit_bootstrap(gadget)` 为已有 context 添加使用 `Separate` 投影的 CBS。

PBS 和 CBS 都要求 `key_switching`。CBS 输出环/gadget 密文，完整组合仍保留 KS 供后续 LWE 返回。`PbsMessageConfig::new(t_in)` 默认输入输出消息模数相同，`.with_output_modulus(t_out)` 只修改输出。消息选择不改变密钥域。

## 参数与密钥域

`PbsParameters<T, M, LM=M>` 分离环模数 Q 和外部 LWE 模数 q，保留相同系数类型 T。`external_lwe` 选择维数 n、q 和外部秘密，`ring_modulus`、`bsk_poly_length` 和 `bsk_secret_distr` 选择环。n 与 N 独立，`2N` 须能由 T 表示；维数和环长度使用 `LweDimension` 和 `PolyLength`。

| 噪声配置 | 用途 |
| --- | --- |
| `external_lwe` 噪声 | q 下新鲜输入加密 |
| `bsk_gadget` 噪声 | Q 下 BR 密钥行、环候选加密及 CBS trace/scheme-switch 行 |
| `key_switching` 噪声 | q 下返回密钥行 |

BR 和 KS 分别使用 `GadgetEncryptionConfig { decomposition, noise_standard_deviation }`，噪声以各自模数下的系数为单位。CBS 的 `output`、`trace` 和 `scheme_switch` 各选择一组 `DecompositionConfig`。分解基和随机采样彼此独立，`level_count: None` 选择最大支持层数，不必然消除截断误差，见[分解精度](../primus_decompose/README.zh_CN.md)。

`ClientKey` 包含独立采样的外部秘密 s 和环秘密 f。只有 f 需要 NTRU 可逆性；外部秘密可为 binary/ternary，无需补零或奇数重量。`client.external_lwe_secret_key()` 返回 q 下的 s，家族客户端工厂检查其记录的模数。完整 PBS/CBS 生成还要求 f 的有符号系数幅度小于显式返回 q。见[参数](src/parameters.rs)和 [NTRU 秘密生成](../primus_ntru/README.zh_CN.md#参数与密钥)契约。

普通 PBS 顺序为 f,Q 下盲旋转 → 逐系数 Q→q 最近舍入 → 相位提取 → q 下 LWE KS 到 s。ManyLUT 共享 BR，再分别返回各输出；`context.allocate_lwe_ciphertext()` 使用 n。LUT 本身是公开的，但 NTRU 提升和 BR 控制会贡献加密噪声。参数构造不建立安全性或完整噪声预算。

## Sparse 系数密钥

Classic binary/ternary 和 sparse fixed-weight binary 支持 PBS、ManyLUT、Boolean、MVB、CBS 和 one-hot。Sparse 须通过 `config.method` 显式选择，`SparseTernary` 秘密分布本身不会选择桶聚合。外部固定重量可以为偶数，仍须满足[共享 sparse 限制](../primus_tfhe/README.zh_CN.md#选择盲旋转算法)。

`SparseNtruBootstrappingKey<T>` 保存 sparse 系数控制，首桶为提升用 NLev 控制，后续桶为加密旋转用 NGSW 控制。优先用 context/key-generator 工厂，原始存储契约见 [sparse 密钥类型](src/sparse.rs)，提升推导见[首次提升推导](../../guides/development/bootstrapping-contracts.md#ntru-first-lifting)。

## 客户端与 LUT

普通 PBS 用 `context.try_generate_keys(rng)` 返回配套 client/server 密钥。外部秘密提供给 `context.encryptor`、`pbs_decryptor` 和 `mvb_decryptor`，公钥输入用 `public_encryptor`。它们从 `config.messages` 派生编码，无需 LUT 或手工 codec。`pbs_lookup_table_compiler()` 和 `compile_mvb_fn` 使用相同默认值，家族 `PbsParameters` 也提供无需变换表的客户端工厂。

输入使用 q 下 Rounded 编码。PBS/ManyLUT 在 Q 下编译 Rounded 输出，再于 q 下解码；MVB 在两端输出模数下均用 Scaled。返回缩放已有相位，不在 q 下重新编码，须预算尺度差异、Q→q 舍入和 KS 误差。相同消息模数也不保证反馈兼容；同钥消息覆盖见[选择输出编码](../primus_tfhe/README.zh_CN.md#选择输出编码)。有界双输入查表目前要求 q=Q。

前半区程序用 `encrypt_padded`，奇数全域用 `encrypt`。通过 `as_mut_view()` 复用输出、`as_view()` 读取，`decrypt_phase` 保留诊断用途。`parameters.try_generate_public_key(external_secret, rng)` 生成外部 LWE 公钥，不是 NTRU 环公钥；须计入其[额外噪声](../primus_lwe/README.zh_CN.md#公钥加密)。

## Boolean 客户端与门

配置 `PbsMessageConfig::new(4)` 后使用 context 的 Boolean 客户端/evaluator 工厂。串联门要求两个消息域均为四，使用普通 PBS 材料即可。见[共享 Boolean 契约](../primus_tfhe/README.zh_CN.md#boolean-门)。

## CBS 与示例

创建 CBS context 后调用 `context.try_generate_circuit_bootstrap_keys(rng)`，得到 `(ClientKey, CircuitBootstrapServerKey)`，包含 BR、返回 KS 和 CBS 材料，`server.server_key()` 也支持普通 PBS。通过 `try_with_circuit_bootstrap` 添加 CBS 后，应使用该 CBS 生成入口，不能用 `try_generate_keys` 替代。

通过 `compile_cbs_identity`、`compile_cbs_fn` 或 `compile_cbs_slice` 编译恒等/自定义函数，再用 `circuit_bootstrap_evaluator_with_lookup_table` 绑定，`circuit_bootstrap_evaluator` 是恒等快捷入口。输入使用 `context.encryptor`，输出为 f 下 gadget 尺度的 NGSW，不执行普通 LWE 返回。CMux 要求完整输入域上的 F 为 bit。

`accumulator_client(client.accumulator_ntru_secret_key(), t_ring)` 准备 Q 下的 Scaled 候选，t_ring 独立于外部输入 t；候选须共享 f、Q 和编码。CBS 绑定完整输出 basis，BR 分解须能解析 LUT 和最小输出 gadget 尺度。布局检查不证明实际秘密身份或足够的噪声余量。见 [CBS 消费与示例](../primus_tfhe/README.zh_CN.md#cbs-输出与消费)。

NTT reverse trace 使用模逆元。Scheme switching 的输入误差乘 f，分解误差乘 f²；发布 `NGSW_f[f]` 需要有依据的 key-dependent-message/circular-security 假设，见 [NTRU 契约](../primus_ntru/README.zh_CN.md#同一秘密下的-scheme-switching)。

`CbsConfig.projection` 选择仅输出 NGSW 时的算法：`Separate`（枚举默认值）、`FusedLastStage`、`FusedLastThreeStages` 或 `PairedTrace`。NTRU NTT 性能预设显式使用 `PairedTrace`。NLEV-only 和双输出保留独立 trace/SS，切换策略需要重新评估噪声预算，见 [`NtruProjectionMethod`](../primus_ntru/src/scheme_switch/mod.rs)。在准备参数/密钥前选择；见 [NTT 配置示例](../primus_tfhe_ntru_ntt/README.zh_CN.md#参数与表示)。

## One-hot CBS

`context.one_hot_evaluator(&server)?` 使用相同 CBS 组合，支持 classic binary/ternary 或 sparse fixed-weight binary BR。要求 t=2M、M=2^tau 且 tau>=1，用 `encrypt_padded` 加密 `0..M`。输出有 L 层时，令 `W=next_power_of_two(L)`，要求 `2MW<=N`。

| 输出 | 分配 / 求值 |
| --- | --- |
| 完整 NLev selectors | `allocate_nlev_output` / `one_hot_nlev_to` |
| 完整 NGSW selectors | `allocate_ngsw_output` / `one_hot_ngsw_to` |
| 仅非零 NGSW 分支 | `allocate_nonzero_ngsw_output` / `one_hot_nonzero_ngsw_to` |
| 两种表示 | `one_hot_to`，或用 `one_hot_nlev_and_nonzero_ngsw_to` 生成完整 NLev 加非零 NGSW |

完整输出覆盖 δ_r(m)，r=0..M-1；紧凑 NGSW 的位置 r-1 对应 r=1..M-1，m=0 时这些目标 bit 均为零。`cmux_k_to` 以 C0 为默认项消费非零控制。NLev 输出为 Q 下系数表示，用于公开多项式提升前须变换；NGSW 使用后端变换表示供 CMux 消费。

通过 `nlev_selectors`、`ngsw_selectors` 或 `nonzero_ngsw_selectors` 借用分支视图。`selector(r)` 使用数学分支编号，`iter()` 返回 `(r, ciphertext)`；视图不分配。完整布局、basis 和表示要求见 [selector 类型](src/one_hot/selectors.rs)及后端 evaluator。

令 S=N/M、A=N/(2MW)。正确选择要求量化相位 `u_bar=S*m+W*e mod 2N` 满足 `-A<=e<A`，窗口左闭右开。e 包含输入噪声、编码舍入及逐坐标量化误差；形状检查不能证明该保护区条件或输出可解码。见 [one-hot 推导](../../guides/development/bootstrapping-contracts.md#one-hot-cbs)。

独立仓库中的[高精度 LUT 库](../../../primus_high_prec_lut/README.zh_CN.md)处理多个输入 chunk 和表多项式，默认采用 classic BR，sparse 可显式选择。

## NTRU→LWE 返回

普通 PBS/MVB evaluator 已处理返回。独立系数域结果使用本家族重导出的 `primus_ntru::LweReturnEvaluator` 和 `LweReturnBatchWorkspace`。通过 `LweReturnEvaluator::new(server.key_switching_key(), q_modulus)` 绑定服务端返回密钥与目标 q，按需准备标量或批量 scratch。单系数、共享输入前缀及不同输入流的用法与数值条件见 [NTRU 返回流程与契约](../primus_ntru/README.zh_CN.md#独立-lwe-返回)。

## Features 与进一步阅读

默认 features 为空，本家族不启用 NTT/FFT；`simd` 转发给算术依赖。同态求值须选择具体后端。

[API 源码](src/lib.rs) · [共享操作与编码](../primus_tfhe/README.zh_CN.md) · [数值契约](../../guides/development/bootstrapping-contracts.md)
