# primus_tfhe_glwe_ntt

[English](README.md) | 简体中文

> [!WARNING]
> 本库属于实验性 [Primus FHE](../../README.zh_CN.md) workspace。API 和数值契约可能发生不兼容变更。

GLWE TFHE 的 NTT 后端，支持 PBS、ManyLUT、分解式 MVB、Boolean 门和 CBS。

## 快速开始

```sh
cargo run -p primus_tfhe_glwe_ntt --release --example ntt_basic
```

从 [`experimental`](src/experimental.rs) 选择操作预设。这些教学参数的安全性和失败概率尚未评估。

```rust
use primus_ntt::U64NttTable as Table;
use primus_tfhe_glwe_ntt::{TfheContext, experimental};

let config = experimental::CLASSIC_PBS_U64;
let context = TfheContext::<u64, Table>::try_from_pbs_config(config)?;
```

用 `config.messages = PbsMessageConfig::new(t_in).with_output_modulus(t_out)` 设置输入与输出消息模数。CBS 使用 `CbsConfig` 和 `TfheContext::try_from_cbs_config`。

## 操作示例

示例均使用 u64。替换快速开始命令中的示例名称即可运行。

| 用途 | 示例 |
| --- | --- |
| 连续两次 PBS | [ntt_basic](examples/ntt_basic.rs) |
| Boolean 访问控制 | [ntt_boolean](examples/ntt_boolean.rs) |
| ManyLUT 同时返回等级和标志 | [ntt_many_lut](examples/ntt_many_lut.rs) |
| CBS 谓词、CMux、环加法和 LWE 返回 | [ntt_circuit_bootstrap](examples/ntt_circuit_bootstrap.rs) |
| MVB 从一个输入返回 17 个阈值标志 | [mvb_thresholds](examples/mvb_thresholds.rs) |
| 独立 q/Q 下两种顺序的 Block PBS | [ntt_two_moduli](examples/ntt_two_moduli.rs) |
| MSB Boolean CBS 选择加密限额 | [ntt_msb_cbs](examples/ntt_msb_cbs.rs) |

保留 context、密钥与表以复用。每个并发请求使用独立的可变 evaluator。PBS/ManyLUT 使用 `pbs_decryptor`，Scaled MVB 使用 `mvb_decryptor`。

## 参数与表示

环模数 Q 为支持 NTT 表所需本原 `2N` 次单位根的显式素数。`U32NttTable` 和 `U64NttTable` 分别要求 Q 小于 `2^30` 和 `2^62`。变换域材料必须遵循该表的根与顺序。 [NTT 构造条件](../primus_ntt/README.zh_CN.md#构造约束)

BR→KS 在小 LWE 秘密及 q 下输入和返回，KS→BR 在展平的环秘密及 Q 下输入和返回。Boolean 门要求 q=Q。Classic 与 Block 均支持两种顺序。 [参数与密钥域](../primus_tfhe_glwe/README.zh_CN.md#参数与外部密钥域)

原始 Block BR 见[单输入与批量工作区](src/block/blind_rotation.rs)。批量工作区对独立输入分别返回一个 GLWE。

## Features

可选 `simd` feature 启用 nightly SIMD 内核。

## 基准

```sh
cargo bench -p primus_tfhe_glwe_ntt --bench pbs
```

| 目标 | 计时范围 |
| --- | --- |
| [pbs](benches/pbs.rs) | u32 或 u64 的一次完整 Classic PBS |
| [many_lut](benches/many_lut.rs) | 一次双输出 ManyLUT |
| [mvb](benches/mvb.rs) | 一次 17 输出阈值 MVB |
| [cbs](benches/cbs.rs) | 一次 CBS 谓词、CMux 和单系数 LWE 返回 |
| [cbs_identity](benches/cbs_identity.rs) | 以变换域 GGSW 为终点的恒等 CBS |
| [modulus_domains](benches/modulus_domains.rs) | 两种 PBS 顺序下 q=Q 与 q=1024 的完整 PBS 对照 |

建钥、分配和正确性校验均在计时循环外。负载选择和参数见[测试指南](../../guides/development/testing.md#tfhe-benchmarks)。

## 进一步阅读

[操作指南](../primus_tfhe/README.zh_CN.md#选择同态操作) · [数值契约](../../guides/development/bootstrapping-contracts.md) · [性能指南](../../guides/performance/README.zh_CN.md)
