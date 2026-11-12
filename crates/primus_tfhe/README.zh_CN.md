# primus_tfhe

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) 工作区。API 和数值契约尚未稳定，后续可能发生不兼容变更。

GLWE 和 NTRU 共用的 LWE 客户端、LUT 编译器和 PBS 接口。完整示例见各具体后端。

## 选择同态操作

设 `t` 为输入消息模数，`N` 为环长，`k` 为输出数。普通 PBS 使用无符号 Rounded 输入。

| 任务 | 输入域 | 程序及输出 |
| --- | --- | --- |
| 一元函数 | 前半区 `0..ceil(t/2)` | `compile_fn` 或 `compile_slice`，一个 Rounded LWE |
| 奇数全域 | `0..t`，奇数 `3 ≤ t ≤ N` | `compile_odd_full_domain_fn` 或 `compile_odd_full_domain_slice`，一个 Rounded LWE |
| ManyLUT | 一个前半区输入，`ceil(t/2) ≤ N/next_power_of_two(k)` | `compile_interleaved_fn` 或 `compile_interleaved_slice`，k 个 Rounded LWE |
| 分解式 MVB | 一个非空前半区前缀 | `compile_mvb_fn`，k 个 Scaled LWE |
| 有界双输入函数 | `x<B`、`y<R`、`B*R≤ceil(t/2)` | `BivariateLookupTable`，一个 Rounded LWE |
| Boolean 门 | t=4 的 Rounded 0/1 | `BooleanEvaluator`，Boolean LWE |
| CBS 后接 CMux | 前半区输入或 GLWE MSB bit | `CbsEvaluator`，GGSW/NGSW 控制 |
| One-hot CBS | t=2M 的一个带 padding 的 chunk | `one_hot_evaluator`，NLEV/NGSW selector |

ManyLUT 用旋转分辨率换取输出数。三个输出需要四条槽位，返回三个密文。MVB 保留步长一，需计入因子放大的噪声。双输入 PBS 的输入共用秘密和编码，输入与输出 codec 共用密文模数。参见[旋转与噪声条件](../../guides/development/bootstrapping-contracts.md)及[双输入契约](src/lookup_table/bivariate.rs)。

## Crate 分工与能力

| 家族 | NTT 后端 | Fourier 后端 |
| --- | --- | --- |
| [GLWE 参数与客户端](../primus_tfhe_glwe/README.zh_CN.md) | [GLWE NTT](../primus_tfhe_glwe_ntt/README.zh_CN.md) | [GLWE Fourier](../primus_tfhe_glwe_fourier/README.zh_CN.md) |
| [NTRU 参数与客户端](../primus_tfhe_ntru/README.zh_CN.md) | [NTRU NTT](../primus_tfhe_ntru_ntt/README.zh_CN.md) | [NTRU Fourier](../primus_tfhe_ntru_fourier/README.zh_CN.md) |

GLWE 的两种 PBS 顺序都支持 PBS、ManyLUT、MVB 和 CBS。NTRU 后端也提供 one-hot CBS。四个后端均提供秘密密钥及 LWE 公钥客户端。Fourier 使用 native 环模数，提供 RustFFT 与 TFHE-FFT。示例参数的安全性和失败概率尚未评估，见[参数目录](../../guides/development/tfhe-parameters.md)。

## 选择盲旋转算法

显式设置 `config.method`。`Classic` 支持二进制和三元分布，包括固定重量二进制。直接分块聚合使用 `Block` 和 `SecretKeyDistr::BlockBinary { block_size, occupancy }`，逻辑秘密长度须为正块宽的整数倍。`AtMostOne` 允许空块，使用独立加密的 dummy。`ExactlyOne` 要求每块有一个 1，省去 dummy。Classic 也可使用这两种分块分布。NTRU Fourier Block 要求 u64。

从分桶 Sparse 迁移固定重量配置时，选择 Classic、重新生成计算密钥并评估噪声。采用 Block 会改变秘密分布，需要独立评估。 [Block 数值契约](../../guides/development/bootstrapping-contracts.md#classic-ternary-and-block-rotation)

## 客户端与服务端边界

PBS、ManyLUT 或 MVB 用 `TfheContext::try_from_pbs_config` 和 `context.try_generate_keys(rng)`。CBS 用 `try_from_cbs_config` 和 `try_generate_circuit_bootstrap_keys`，其密钥包的 `server.server_key()` 也能用于普通 PBS。

客户端保留秘密密钥，向服务端提供计算密钥、密文及必要的环候选密文。服务端编译公开 LUT 并求值。跨请求复用 context、密钥、编译后的程序和 evaluator。通过 `as_view()`、`as_mut_view()` 调用 `_to` 接口复用输出。并发 worker 各自持有可变 evaluator。

原始密文不携带密钥或编码身份。使用配套秘密及显式模数下的规范系数，并将 Fourier 材料绑定到原 FFT table 实例。 [数值契约](../../guides/development/bootstrapping-contracts.md#ciphertext-domains-and-return)

### 选择输出编码

`PbsMessageConfig::new(t_in)` 默认输入输出模数相同，用 `.with_output_modulus(t_out)` 单独设置输出域。`from_input_bits(4)` 使用模数 32，对应 16 个带 padding 的输入和 32 个全域输出值。

| 操作 | 程序工厂 | 输出解码器 |
| --- | --- | --- |
| PBS 和 ManyLUT | `pbs_lookup_table_compiler()` | `pbs_decryptor`，Rounded 输出 |
| MVB | `compile_mvb_fn(domain_len, output_count, function)` | `mvb_decryptor`，Scaled 输出 |

用 `context.encryptor(external_secret)` 或 `public_encryptor(&public)` 准备输入。前半区 LUT 用 `encrypt_padded`，奇数全域程序用 `encrypt`。`encrypt_centered` 使用中心化表示，普通 LUT 要求无符号输入。

同一密钥下更换消息空间时，使用 `pbs_lookup_table_compiler_with_messages`、`encryptor_with_message_modulus`（或 `public_encryptor_with_message_modulus`）和 `pbs_decryptor_with_message_modulus`。MVB 用 `compile_mvb_fn_with_messages` 和所选输出模数的 `ring_return_decryptor`。把输出接入后续 PBS 前，核对编码、已编程值域和噪声余量。

## Boolean 门

设置 `PbsMessageConfig::new(4)`，使用 Boolean 客户端及 evaluator 工厂和普通 PBS 密钥。级联要求输入输出均为 t=4，GLWE 还要求 q=Q。 [GLWE 示例](../primus_tfhe_glwe_ntt/examples/ntt_boolean.rs) · [NTRU 示例](../primus_tfhe_ntru_ntt/examples/ntru_ntt_boolean.rs)

## CBS 输出与消费

用 `compile_cbs_fn` 或 `compile_cbs_slice` 编译函数，再由 `circuit_bootstrap_evaluator_with_lookup_table` 绑定。恒等函数使用 `circuit_bootstrap_evaluator`。GLWE 的 padded 和 MSB 输入都通过 `cbs_encryptor` 加密。NTRU 用 context 的 encryptor 调用 `encrypt_padded`。

CBS 输出 gadget 尺度的环控制密文。CMux 要求函数在完整编程域上为 bit。用 `accumulator_client(ring_secret, t_ring)` 准备候选密文，其中 `t_ring` 指定 Q 下独立的 Scaled 消息域。候选共用环秘密、模数和编码。NTRU one-hot 的 `cmux_k_to` 消费分支 1 到 M−1，默认选择 C0。 [CBS 契约](../../guides/development/bootstrapping-contracts.md#ordinary-cbs-and-consumption) · [One-hot API](../primus_tfhe_ntru/README.zh_CN.md#one-hot-cbs)

## 固定尺度分解式 MVB

MVB 对一个带 padding 的输入计算多个函数。使用显式奇数 Q，或实际 Scaled 输出尺度为偶数的 native 环。需计入因子放大和 Fourier 变换误差。Scaled 输出（包括数字阈值标志）使用 `mvb_decryptor` 解码。 [MVB 契约](../../guides/development/bootstrapping-contracts.md#factorized-mvb)

## Features 与进一步阅读

默认无 feature。`simd` 转发至算术依赖。 [API 源码](src/lib.rs) · [编译与绑定错误](src/error.rs)
