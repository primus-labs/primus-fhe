# primus_tfhe_glwe_fourier

[English](README.md) | 简体中文

> [!WARNING]
> 本库属于实验性 [Primus FHE](../../README.zh_CN.md) workspace。API 和数值契约可能发生不兼容变更。

GLWE TFHE 的 Fourier 后端，支持 PBS、ManyLUT、分解式 MVB、Boolean 门和 CBS。

## 快速开始

```sh
cargo run -p primus_tfhe_glwe_fourier --release --example fourier_basic
```

从 [`experimental`](src/experimental.rs) 选择操作预设。这些教学参数的安全性和失败概率尚未评估。

```rust
use primus_fft::RustFftTable as Table;
use primus_tfhe_glwe_fourier::{TfheContext, experimental};

let config = experimental::CLASSIC_PBS_U64;
let context = TfheContext::<u64, Table>::try_from_pbs_config(config)?;
```

用 `config.messages = PbsMessageConfig::new(t_in).with_output_modulus(t_out)` 设置输入与输出消息模数。CBS 使用 `CbsConfig` 和 `TfheContext::try_from_cbs_config`。

## 操作示例

示例均使用 u64。替换快速开始命令中的示例名称即可运行。

| 用途 | 示例 |
| --- | --- |
| 连续两次 PBS | [fourier_basic](examples/fourier_basic.rs) |
| Boolean 访问控制 | [fourier_boolean](examples/fourier_boolean.rs) |
| ManyLUT 同时返回等级和标志 | [fourier_many_lut](examples/fourier_many_lut.rs) |
| CBS 谓词、CMux、环加法和 LWE 返回 | [fourier_circuit_bootstrap](examples/fourier_circuit_bootstrap.rs) |
| MVB 从一个输入返回 17 个阈值标志 | [fourier_mvb_thresholds](examples/fourier_mvb_thresholds.rs) |
| MSB Boolean CBS 选择加密限额 | [fourier_msb_cbs](examples/fourier_msb_cbs.rs) |

保留 context、密钥与表以复用。每个并发请求使用独立的可变 evaluator。PBS/ManyLUT 使用 `pbs_decryptor`，Scaled MVB 使用 `mvb_decryptor`。

## 参数与表示

环使用 u32 或 u64 的 `NativeModulus<T>`，小 LWE 模数 q 可独立设置。变换域密钥、值和 evaluator 共用同一 FFT 表实例。 [Fourier 表示](../primus_fft/README.zh_CN.md) · [系数域建钥与迁移](../primus_glwe/README.zh_CN.md#加密与解密)

BR→KS 在小 LWE 秘密及 q 下输入和返回，KS→BR 在展平的环秘密及 Q 下输入和返回。Boolean 门要求 q=Q。Classic 与 Block 均支持两种顺序。 [参数与密钥域](../primus_tfhe_glwe/README.zh_CN.md#参数与外部密钥域)

启用 `split-trace` 后，`CbsConfig.fourier_trace_precision` 可在 native u64、rank 1 且环秘密绝对值不超过 1 时选择 `Split35`。CBS 示例接受 `-- --split-trace`。 [Trace 条件与误差预算](../../guides/development/bootstrapping-contracts.md#glwe-fourier-error-budgets)

## Features

默认启用 `rustfft` 和 `split-trace`。示例使用 RustFFT。通用基准对每个启用的引擎分别注册用例。只测 TFHE-FFT 时使用 `--no-default-features --features tfhe-fft`。
使用 TFHE-FFT 单独测 Split35 时额外启用 `split-trace`。

可选 `simd` feature 启用 nightly SIMD 内核。

## 基准

```sh
cargo bench -p primus_tfhe_glwe_fourier --bench pbs
```

| 目标 | 计时范围 |
| --- | --- |
| [pbs](benches/pbs.rs) | u32 或 u64 的一次完整 Classic PBS |
| [many_lut](benches/many_lut.rs) | 一次双输出 ManyLUT |
| [mvb](benches/mvb.rs) | 一次 17 输出阈值 MVB |
| [cbs](benches/cbs.rs) | 一次 CBS 谓词、CMux 和单系数 LWE 返回 |
| [cbs_identity](benches/cbs_identity.rs) | 以变换域 GGSW 为终点的恒等 CBS |
| [modulus_domains](benches/modulus_domains.rs) | 两种 PBS 顺序下 q=Q 与 q=1024 的完整 PBS 对照，要求 `tfhe-fft` |

建钥、分配和正确性校验均在计时循环外。负载选择和参数见[测试指南](../../guides/development/testing.md#tfhe-benchmarks)。

## 进一步阅读

[操作指南](../primus_tfhe/README.zh_CN.md#选择同态操作) · [数值契约](../../guides/development/bootstrapping-contracts.md) · [性能指南](../../guides/performance/README.zh_CN.md)
