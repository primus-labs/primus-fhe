# primus_rns

[English](README.md) | 简体中文

`primus_rns` 提供剩余数系统基、CRT 组合与分解、基转换，以及 [Primus FHE](../../README.zh_CN.md) 使用的 Hybrid `Q`/`P` 运算。其无分配的批量路径在平坦 slice 上工作，并使用调用方拥有的可复用 workspace。

> [!WARNING]
> 本 crate 属于实验性的 Primus FHE workspace。其 API、数据布局和数值契约尚不稳定，可能随时发生不兼容修改。

## 主要类型

| 类型 | 职责 |
| --- | --- |
| `Residues<S>` | 一个值在有序 RNS 基下的剩余表示 |
| `ResidueFactors<S>` | 一个值在有序 RNS 基下的预计算乘法因子 |
| `RNSBase<T, M>` | 非空、模数两两互素的 RNS 基及其 CRT 预计算 |
| `BaseConverter<T, M>` | 在两个 RNS 基之间执行 fast 或 corrected 转换的预计算 |
| `CenteredBaseConverter` | 受支持 u64 基的精确居中转换 |
| `HpsRns` | 预计算的 HPS 系数运算 |
| `HybridRNS` 与 `HybridRNSPartitioning` | 活跃层及全链固定分区规则 |

重复执行多项式运算时通常使用 [`BarrettModulus`](../primus_modulus/README.zh_CN.md)。

## 示例

`Residues<S>` 借用或拥有一个值按基顺序排列的规范剩余类。调用时提供匹配的基。
通过 `decompose_factors` 为缩放分解准备 `ResidueFactors<S>`。

```rust
use primus_modulus::BarrettModulus;
use primus_rns::{RNSBase, Residues};

let moduli = [3_u64, 5, 7].map(BarrettModulus::new);
let base = RNSBase::new(&moduli).unwrap();

let value = base.compose(Residues(&[2, 4, 6]));
assert_eq!(value.digits(), &[104]);
assert_eq!(base.decompose(value.view()).as_ref(), [2, 4, 6]);
```

`compose` 返回 `[0, Q)` 中的规范代表元，其中 `Q` 是基中所有模数的乘积。

## 数据布局

批量 residue 始终采用 modulus-major 布局。对于 `k` 个值和模数 `q_0, ..., q_(n-1)`，长度为 `n * k` 的 slice 排列如下：

```text
[a_0 mod q_0, ..., a_(k-1) mod q_0,
 a_0 mod q_1, ..., a_(k-1) mod q_1,
 ...]
```

批量大整数按值分组，每个值占据一个连续、定宽的小端 limb 分块，宽度为
`RNSBase::big_uint_value_len()`。

[`CrtPolynomial`](../primus_poly/README.zh_CN.md) 使用相同的 modulus-major 系数布局。将其系数 slice 传给批量 API，以多项式长度作为值的数量，无需重排数据。`primus_rns` 不依赖多项式容器类型。

## RNS 基

`RNSBase::new` 检查基非空且模数两两互素。复用已准备的基，用
`prefix(count)` 派生非空有序前缀。自定义 context 需满足
[RNS 基契约](src/base/mod.rs)，包括 Shoup 因子要求的模数范围。

用 `compose*` 和 `decompose*` 执行 CRT 转换。小模数的居中提升使用
[`wrapping_decompose*`](src/base/small.rs)。模数为二时保留两个二进制值。
该 API 的缩放累加方法向规范累加器添加结果，乘法因子须匹配对应的基。

## 基转换

使用已准备的基构造转换器，按批量大小复用匹配的工作区或 scratch。
并发运算各自使用可变存储。

| 操作 | 含义 |
| --- | --- |
| [`fast_convert*`](src/converter/fast.rs) | 多模数基上的近似 CRT 提升，结果表示 `x + kQ`。调用方的算法须允许额外的 `Q` 倍数项。单模数输入使用精确约简。 |
| [`corrected_convert_array`](src/converter/corrected.rs) | 向单个输出模数作居中修正。半区边界附近的浮点修正可能相差一个 `Q` 倍数项。 |
| [`CenteredBaseConverter`](src/converter/centered.rs) | 小于 `2^62` 的奇数 u64 基上的精确居中转换，支持一个或多个输出模数。 |

多模数转换使用跨模数点积，操作数可以超过目标模数。Barrett 接受小于
`2^(T::BITS - 2)` 的操作数。自定义 context 须满足[转换范围契约](src/converter/fast.rs)。

### HPS 系数运算

[`HpsRns`](src/hps.rs) 为互素且小于 `2^62` 的奇数 u64 基和正尺度 `t` 准备资源。
复用工作区可完成精确居中扩展、带有界单侧残差的 P/Q 预缩放，以及由一致的 Q/P
剩余类精确计算 `nearest(t*z/P) mod Q`。
[BFV 契约](../../guides/development/bfv-evaluation.md#hpspoverq-backend)说明使用这些
运算的算法及辅助基、误差条件（English）。

## Hybrid RNS

`HybridRNS` 按 `Q || P` 顺序组合密文基 `Q` 和辅助基 `P`。在同一模数链的非空
有序前缀上使用同一份 `HybridRNSPartitioning`，保持与密钥兼容的分区边界。
[构造器契约](src/hybrid/construction.rs)说明允许的数位数量和活跃层。

近似 ModUp 将一个分区提升到 `Q || P`。流式 ModUp 仅输出转换后的补集 limb，
原分区 limb 由调用方提供。近似 ModDown 将修正项从 `P` 转换到 `Q`，相减后
乘以 `P^-1 mod q_i`。方案自定义的修正项须具有匹配的来源、符号、尺度和有序 Q 基。
参见 [Hybrid API](src/hybrid) 和
[原生 BFV/BGV Hybrid 密钥](../../guides/development/native-hybrid-keys.md)（English），
后者说明这两个方案使用的精确居中修正。

## 调用方契约与 workspace

按基顺序传入规范剩余类和完整缓冲区。组合基中的模数必须两两互素。
输出和 scratch 形状须与批量大小匹配。并发调用使用独立的可变工作区。

## SIMD feature 与基准

可选的 `simd` 启用小值及模算术的 nightly portable SIMD，默认关闭。
[分解基准](benches/decompose.rs)说明其工作负载。

```sh
cargo bench -p primus_rns --bench decompose
```

## 许可证

本 crate 可由你选择使用 [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) 或 [MIT License](../../LICENSE-MIT)。
