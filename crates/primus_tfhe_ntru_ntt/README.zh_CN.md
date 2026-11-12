# primus_tfhe_ntru_ntt

[English](README.md) | 简体中文

> [!WARNING]
> 本库属于实验性 [Primus FHE](../../README.zh_CN.md) workspace。API 和数值契约可能发生不兼容变更。

NTRU TFHE 的 NTT 后端，支持 PBS、ManyLUT、分解式 MVB、Boolean 门和 CBS，以及 one-hot。

## 快速开始

```sh
cargo run -p primus_tfhe_ntru_ntt --release --example ntru_ntt_basic
```

从 [`experimental`](src/experimental.rs) 选择操作预设。这些教学参数的安全性和失败概率尚未评估。

```rust
use primus_ntt::U64NttTable as Table;
use primus_tfhe_ntru_ntt::{TfheContext, experimental};

let config = experimental::CLASSIC_PBS_U64;
let context = TfheContext::<u64, Table, _>::try_from_pbs_config(config)?;
```

用 `config.messages = PbsMessageConfig::new(t_in).with_output_modulus(t_out)` 设置输入与输出消息模数。CBS 使用 `CbsConfig` 和 `TfheContext::try_from_cbs_config`。

## 操作示例

示例均使用 u64。替换快速开始命令中的示例名称即可运行。

| 用途 | 示例 |
| --- | --- |
| 连续两次 PBS | [ntru_ntt_basic](examples/ntru_ntt_basic.rs) |
| Boolean 访问控制 | [ntru_ntt_boolean](examples/ntru_ntt_boolean.rs) |
| Block ManyLUT 同时返回等级和标志 | [ntru_ntt_many_lut](examples/ntru_ntt_many_lut.rs) |
| CBS 谓词、CMux、环加法和 LWE 返回 | [ntru_ntt_circuit_bootstrap](examples/ntru_ntt_circuit_bootstrap.rs) |
| MVB 从一个输入返回 17 个阈值标志 | [ntru_ntt_mvb_thresholds](examples/ntru_ntt_mvb_thresholds.rs) |
| One-hot CBS 和四路加密记录选择 | [ntru_ntt_one_hot](examples/ntru_ntt_one_hot.rs) |

保留 context、密钥与表以复用。每个并发请求使用独立的可变 evaluator。PBS/ManyLUT 使用 `pbs_decryptor`，Scaled MVB 使用 `mvb_decryptor`。

## 参数与表示

环使用支持 NTT 表所需本原 `2N` 次单位根的显式素数 Q。变换域材料必须遵循该表的根与顺序。 [NTT 构造条件](../primus_ntt/README.zh_CN.md#构造约束)

PBS 在环秘密 f 和 Q 下求值，再依次执行 Q→q 舍入、提取与 LWE KS。CBS 和 one-hot 输出 gadget 密文，消费后可通过 `return_ring_at_to` 返回选定系数。 [NTRU 参数与密钥域](../primus_tfhe_ntru/README.zh_CN.md#参数与密钥域)

`CbsConfig.projection` 在建钥前选择 NGSW 投影。CBS 和 one-hot 预设使用 `PairedTrace`。NLEV 和双输出使用独立 trace 与 scheme switch。 [支持的策略](../../guides/development/bootstrapping-contracts.md#ntru-cbs-precision-and-projection-support)

## Features

可选 `simd` feature 启用 nightly SIMD 内核。

## 基准

```sh
cargo bench -p primus_tfhe_ntru_ntt --bench pbs
```

| 目标 | 计时范围 |
| --- | --- |
| [pbs](benches/pbs.rs) | u32 或 u64 的一次完整 Classic PBS |
| [many_lut](benches/many_lut.rs) | 一次双输出 ManyLUT |
| [mvb](benches/mvb.rs) | 一次 17 输出阈值 MVB |
| [cbs](benches/cbs.rs) | 一次 CBS 谓词、CMux 和单系数 LWE 返回 |
| [one_hot](benches/one_hot.rs) | 三个非零 NGSW selector 与四路 CMux |

建钥、分配和正确性校验均在计时循环外。负载选择和参数见[测试指南](../../guides/development/testing.md#tfhe-benchmarks)。

## 进一步阅读

[操作指南](../primus_tfhe/README.zh_CN.md#选择同态操作) · [数值契约](../../guides/development/bootstrapping-contracts.md) · [性能指南](../../guides/performance/README.zh_CN.md)
