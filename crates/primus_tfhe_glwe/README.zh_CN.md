# primus_tfhe_glwe

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

与后端无关的 GLWE-TFHE 参数及 LWE 客户端。Context、服务端密钥、evaluator 和完整示例见 [NTT](../primus_tfhe_glwe_ntt/README.zh_CN.md) 或 [Fourier](../primus_tfhe_glwe_fourier/README.zh_CN.md) 后端。客户端密文为 LWE，GLWE 是累加器家族；操作及编码选择见[公共指南](../primus_tfhe/README.zh_CN.md)。

## 实验配套参数

从具体后端的 `experimental::*_U64` 操作配置开始。这些教学参数不是经过安全性或失败概率认证的预设，详见[参数条件](../../guides/development/tfhe-parameters.md#scope-of-paired-parameter-entries)。

| 配置 | 用途 |
| --- | --- |
| `PbsConfig` | PBS、ManyLUT 和 MVB：small LWE、accumulator/BSK、BR 方法、必需 KS、PBS 顺序及消息域 |
| `CbsConfig { pbs, gadget, input_encoding, fourier_trace_precision }` | 相同 PBS 域，加上 CBS output、trace 和 scheme-switch 分解 |

使用后端 `TfheContext::try_from_pbs_config` / `try_from_cbs_config`。显式准备参数用 `PbsParameters::try_from_config` 或 `CbsParameters::try_from_config(cbs_config)`，`CbsParameters::try_with_config` 接收已有 PBS 参数。`try_with_circuit_bootstrap(gadget, input_encoding, fourier_trace_precision)` 可为已有 context 添加 CBS。

两种配置都要求 `key_switching`。CBS 阶段输出环/gadget 密文，完整密钥组合仍保留 KS，用于输入准备或后续 LWE 返回。`PbsMessageConfig::new(t_in)` 默认输入输出消息模数相同，`.with_output_modulus(t_out)` 只修改输出。消息选择不改变密钥域。

## 参数与外部密钥域

`PbsConfig<T, M, LM = M>` 将小 LWE 的 q（`small_lwe.cipher_modulus`，reducer LM）与累加环 Q（`ring_modulus`，reducer M）分开。现有同域预设给这两个字段设置相同值。`small_lwe` 描述小维数 BR 控制秘密及新鲜加密噪声。`bsk_dimension`、`bsk_poly_length` 和 `bsk_secret_distr` 描述 accumulator/BSK 共用的环秘密及布局，`bsk_gadget` 指定 BSK 分解及行噪声。公开的 `(0, LUT * X^(-b))` 初始化不采样加密噪声。

`GadgetEncryptionConfig { decomposition, noise_standard_deviation }` 分别配置 BR 和 KS。分解使用 `DecompositionConfig { log_basis, level_count }`，`level_count: None` 选择支持的最大层数，但仍可能丢弃低位，见[分解精度](../primus_decompose/README.zh_CN.md)。维数和环长度使用 `LweDimension`、`GlweDimension` 和 `PolyLength`。

| 噪声配置 | 用途 / 系数域 |
| --- | --- |
| `small_lwe` 噪声 | q 域的新鲜 small-LWE 加密 |
| `bsk_gadget` 噪声 | Q 域的 BSK 行、环候选加密、KS→BR 新鲜外部加密、CBS trace/scheme-switch 行 |
| `key_switching` 噪声 | 两种 PBS 顺序下的 Q 域环 KS 行 |

所有标准差以系数为单位，KS 噪声独立于 BR 噪声。CBS 的 `output`、`trace` 和 `scheme_switch` 分解彼此独立，trace/scheme-switch 加密使用累加器噪声。

| `PbsOrder` | PBS 链 | 外部秘密 / 维数 / 模数 |
| --- | --- | --- |
| `BootstrapKeyswitch` | BR(Q) → 环 KS(Q) → compact extraction → MS Q→q | Small LWE / n / q |
| `KeyswitchBootstrap` | Inverse extraction(Q) → 环 KS(Q) → compact extraction → MS Q→q → BR(Q) → full extraction | 展平 GLWE / kN / Q |

两种顺序均返回各自外部秘密和模数下。q=Q 时跳过转换遍历；模数转换逐密文系数舍入，不能把 q 域 residue 直接解释为 Q 域 residue。`external_modulus()` 在两域使用同一 reducer 类型时返回按 order 选择的外部模数；`ring_modulus()` 明确表示 Q，`external_modulus_value()` 按顺序选择外部模数（`None` 表示 native torus）。用 `client.external_lwe_secret_key()` 取得它，`context.allocate_lwe_ciphertext()` 使用该维数。Small secret 须为 binary 或 ternary，满足 `n<=kN`，`2N` 须能由系数字宽表示。不支持 Gaussian small secret；累加秘密可为 Gaussian，但须满足后端幅度界。参数兼容不证明秘密身份或噪声/安全预算，完整数值契约见 [PbsParameters](src/parameters.rs)。

底层 GLWE 盲旋转接收独立准备的 `RotationModulusSwitch<T>`，对应密钥的输入 q 和环旋转域 2N。普通 PBS 使用步长 1，交错操作使用 LUT 补齐后的输出宽度。Context evaluator 自动完成绑定，应用无需管理量化器；详见[旋转量化](../primus_tfhe/src/rotation.rs)和后端 BR 契约。

## Sparse 系数密钥

Classic binary/ternary 和 sparse fixed-weight binary 均支持两种顺序下的 PBS、ManyLUT、MVB 和 CBS。Sparse 须显式设置 `config.method = BlindRotationMethod::Sparse { copy_count, bucket_count }`，遵循[共享选择规则](../primus_tfhe/README.zh_CN.md#选择盲旋转算法)。

两后端共享 `SparseGlweBootstrappingKey<T, M>` 系数存储，NTT 使用 Barrett 剩余类，Fourier 使用 Native 系数，不能互换。优先用 context/key-generator 工厂和普通 evaluator；存储及导入契约见 [sparse 密钥类型](src/sparse.rs)。

## 客户端与 LUT

普通 PBS 通过 `context.try_generate_keys(rng)` 返回配套 client/server 密钥。外部秘密传给 `context.encryptor`、`pbs_decryptor` 或 `mvb_decryptor`；公钥输入用 `public_encryptor`。它们从 `config.messages` 派生编码，无需 LUT 或手工 codec。`pbs_lookup_table_compiler()` 和 `compile_mvb_fn` 使用相同选择，家族 `PbsParameters` 也提供无需变换表的客户端工厂；其 `pbs_lookup_table_compiler(messages)` 和 `compile_mvb_fn(messages, ...)` 分别准备普通 LUT 编译器和系数域 MVB 程序，支持同类型或异构 reducer。

PBS/ManyLUT 返回采用 Rounded，MVB 返回采用 Scaled。反馈前须保证输入、输出与下一次 PBS 的域兼容。同钥输入输出消息覆盖见[选择输出编码](../primus_tfhe/README.zh_CN.md#选择输出编码)。

前半区程序用 `encrypt_padded`，奇数全域用 `encrypt`。通过 `as_mut_view()` 复用输出、`as_view()` 读取，`decrypt_phase` 保留诊断用途。家族工厂检查拥有型 LWE 私钥的模数，raw view 无法建立该条件。`parameters.try_generate_public_key(external_secret, rng)` 在顺序决定的外部域生成 LWE 公钥，须计入其[额外噪声](../primus_lwe/README.zh_CN.md#公钥加密)。

## Boolean 与 CBS

Boolean 门封装目前要求 q=Q、`PbsMessageConfig::new(4)` 及普通 PBS 材料。Context 的 Boolean 工厂接收密钥而无需 codec，输出按[共享 Boolean 契约](../primus_tfhe/README.zh_CN.md#boolean-门)串联。

CBS 创建对应 context 后，调用 `context.try_generate_circuit_bootstrap_keys(rng)` 得到 `(ClientKey, CircuitBootstrapServerKey)`，其 `server_key()` 也支持普通 PBS。KS→BR 使用 KS 准备 CBS 输入；BR→KS 的 CBS 将结果留在累加环中，但完整组合仍提供返回 KS。

`CbsConfig::input_encoding` 选择 `Padded`（继承 PBS 输入 t）或 `MsbBoolean`（t=2，无 padding bit）。使用 `cbs_encryptor` / `cbs_public_encryptor` 后，两种模式均调用 `encrypt` / `encrypt_to`，客户端检查各自的输入域；普通 `encryptor` 保持 PBS 编码。MSB 编译要求 gadget 权重可精确折半（native Q 下为偶数），准备居中的符号 LUT 并绑定 trace 后修正，但不证明噪声预算。保护区间见 [`CircuitBootstrapLookupTable`](../primus_tfhe/src/lookup_table/circuit_bootstrap.rs)。

通过 `compile_cbs_identity`、`compile_cbs_fn` 或 `compile_cbs_slice` 编译恒等/自定义函数，再用 `circuit_bootstrap_evaluator_with_lookup_table` 绑定；`circuit_bootstrap_evaluator` 是恒等快捷入口。输出使用环秘密下的 gadget 缩放，无输出消息 codec。CMux 要求完整输入域上的 F 为 bit；两后端均支持两种顺序及 classic binary/ternary、sparse binary。

`CbsConfig::fourier_trace_precision` 将 CBS trace 表示保存在准备后的参数中。
NTT 和普通 Fourier 使用 `FourierTracePrecision::Ordinary`；`Split35` 要求
native u64、rank1、环秘密系数幅度不超过1，以及 Fourier 后端的 `split-trace` feature。
它只改变 trace 材料，BR 和 scheme switch 仍为普通表示，不证明浮点精度或完整噪声余量。

`CbsParameters::br_control_codec()` 表示 BR 的小 q 控制输入，包括输入 KS/MS 后的域。它不是 KS→BR 的外部输入编码；该输入使用 `context.cbs_encryptor`。

`accumulator_client(client.glwe_secret_key(), t_ring)` 独立于外部输入模数准备 Scaled 环候选。候选须共享累加秘密、Q 和编码。BR 分解须能解析 LUT 和最小输出 gadget 尺度，布局匹配不能证明噪声余量充分。底层兼容输出 basis 覆盖见后端 `CircuitBootstrapEvaluator` 文档，推荐流程及完整示例见 [CBS 输出与消费](../primus_tfhe/README.zh_CN.md#cbs-输出与消费)。

## Features 与进一步阅读

默认 features 为空，本家族不启用 NTT/FFT；`simd` 转发给算术依赖。同态求值须选择具体后端。

[API 源码](src/lib.rs) · [共享操作与编码](../primus_tfhe/README.zh_CN.md) · [数值契约](../../guides/development/bootstrapping-contracts.md)
