# primus_rns

[English](README.md) | 简体中文

`primus_rns` 提供剩余数系统基、CRT 组合与分解、基转换，以及 [Primus FHE](../../README.zh_CN.md) 使用的 Hybrid `Q`/`P` 运算。其无分配的批量路径在平坦 slice 上工作，并使用调用方拥有的可复用 workspace。

> [!WARNING]
> 本 crate 属于实验性的 Primus FHE workspace。其 API、数据布局和数值契约 尚不稳定，可能随时发生不兼容修改。

## 主要类型

| 类型 | 职责 |
| --- | --- |
| `Residues<S>` | 一个值在有序 RNS 基下的剩余表示 |
| `ResidueFactors<S>` | 一个值在有序 RNS 基下的预计算乘法因子 |
| `RNSBase<T, M>` | 非空、模数两两互素的 RNS 基及其 CRT 预计算 |
| `BaseConverter<T, M>` | 在两个 RNS 基之间执行 fast 或 corrected 转换的预计算 |
| `CorrectedConversionWorkspace<T>` | corrected 批量转换使用的可复用 workspace |
| `HybridRNSPartitioning` | 在 modulus chain 各层之间共享的固定 full-`Q` 分区规则 |
| `HybridRNS<T, M>` | 一个 active Hybrid-RNS level 的基与预计算 |
| `HybridRNSPartition<T, M>` | 一个连续 `Q` 分区及其 approximate ModUp converter |

`T` 是无符号 FHE 整数类型。`M` 是 `primus_reduce::FieldContext<T>`；重复执行 多项式运算时通常使用 [`BarrettModulus`](../primus_modulus/README.zh_CN.md)。

## 示例

`Residues<S>` 以自有或借用存储按基顺序保存一个值的规范 residue，不保留或验证基；批量 API 使用 slice。

`ResidueFactors<S>` 按基顺序保存各模数下的预计算乘法因子；每个因子须匹配对应模数，wrapper 不验证预计算。用 `decompose_factors` 为带缩放的分解准备因子。

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

批量大整数采用相反的分组方式：每个值占据一个连续、定宽的小端 limb 分块， 分块宽度为 `RNSBase::big_uint_value_len()`。

[`CrtPolynomial`](../primus_poly/README.zh_CN.md) 使用相同的 modulus-major 系数布局。将其系数 slice 传给批量 API，以多项式长度作为值的数量，无需重排数据。`primus_rns` 不依赖多项式容器类型。

## RNS 基

`RNSBase::new` 从非空、模数两两互素的 slice 构造基；`from_owned_moduli` 接收模数 vector 的所有权。非法基的构造与扩展返回 `RnsError`。

克隆 `RNSBase` 共享不可变预计算，不复制缓冲区；`extend` / `extend_with` 创建新基，原基保持不变。应复用已准备的基，避免独立重复构造相同基。

`compose*` 和 `decompose*` 执行 CRT 转换。单值入口接受借用的 `Residues` / `BigUint` 视图，可通过拥有存储的 `view()` 或 `view_mut()` 获得。单值分解不限定为 Q 的 limb 宽度，但须遵循模数实现对 limb slice 的契约；批量大整数则使用上述固定宽度。空批量不写入数据，但仍须满足文档中的输出、因子与 scratch 长度要求。

`wrapping_decompose*` 从较小模数 `t` 执行居中提升：小于 `ceil(t / 2)` 的值解释为非负，其余解释为负代表元。`t = 2` 时直接保留 `0` 和 `1`，不会将 `1` 提升为 `-1`。

两个 `add_*decompose_small_values_scaled_assign` 运算将带权 residue 加入已有的规范 accumulator，不清零、不分配临时存储；因子须匹配对应模数。完整操作契约见[基 API](src/base)。

## 基转换

`BaseConverter::new` 共享已准备的输入与输出基，`from_owned_bases` 接收基句柄的所有权。克隆多模数 converter 会复制转换矩阵，重复计算时应复用 converter。

转换面向运行时或派生 Barrett context。多模数转换的跨模数点积须接受可能超过目标模数的源 residue；Barrett 接受小于 `2^(T::BITS - 2)` 的操作数。自定义 context 须满足[转换器算术契约](src/converter/fast.rs)，`FieldContext` 本身不保证这些范围。

两类转换具有不同的数学契约：

- `fast_convert` 和 `fast_convert_array` 执行 SEAL 风格的 approximate CRT lift。输入基包含多个模数时，结果表示某个整数 `x + kQ`，通常不等于规范的 `x mod p_j`。只有外层算法会消去或允许这个 `Q` 倍数项时才能使用。单模数输入 使用精确的直接约简。
- `corrected_convert_array` 应用商修正，将输入解释为 `[-Q/2, Q/2)` 中的居中代表元，要求输出基恰好包含一个模数。多模数输入的修正使用 `f64`，靠近居中边界时仍可能相差一个 `Q` 的倍数，需要在此边界精确转换的应用须采用更高精度方法。完整契约见[修正转换 API](src/converter/corrected.rs)。

通过 `corrected_conversion_workspace` 创建 `CorrectedConversionWorkspace`，在同一 converter 和长度下复用。Fast conversion 接收由 `fast_convert_scratch_len` 或 `fast_convert_array_scratch_len` 确定大小的 scratch slice；空批量不写入数据；corrected 转换仍要求单模数输出基及形状匹配的工作区。每个并发操作使用独立的可变工作区。

## Hybrid RNS

`HybridRNS` 将密文基 `Q` 与辅助基 `P` 组合，并以 `Q || P` 顺序保存完整基。 `HybridRNSPartitioning` 根据 full `Q` 基和请求的 digit 数 `dnum` 推导固定的最大 分区大小 `alpha`：

```text
alpha = ceil(full_q_moduli_count / dnum)
```

固定分区大小必须恰好产生 `dnum` 个非空分区。例如五个 `Q` 模数和 `dnum = 3` 会产生 `[0..2, 2..4, 4..5]`；请求 `dnum = 4` 会被拒绝，因为相同 固定大小只能产生三个分区。

在同一 modulus chain 的较短有序前缀 level 上，应使用 `HybridRNS::from_partitioning`，以保持与 key 兼容的固定分区边界。构造器只验证 active 模数数量；modulus chain 的所有者负责保证前缀关系。

每个分区支持 approximate ModUp 到 `Q || P`；streaming ModUp 只生成转换后的 complement limb，原分区 limb 由调用方提供。ModDown 将 `P` correction 转换到 `Q`，执行减法，再乘以 `P^-1 mod q_i`。

方案需要自定义 correction 时，可组合 `approx_convert_p_to_q_to` 和 `approx_mod_down_from_correction_q_assign`；调用方负责 correction 的来源、符号、缩放及相同 Q 基顺序。这并不自动构成 BFV、BGV 或 CKKS 的降模规则。零长度 Hybrid 运算不写入数据，也不触发流式回调。完整契约见 [hybrid API](src/hybrid)。

## 调用方契约与 workspace

- 除非方法记录了更宽的范围，传给算术和基转换内核的 residue 必须是对应模数下 的规范剩余类。
- 组合进同一个基的模数必须两两互素，包括 `Q || P`。
- Slice 长度、modulus-major 顺序必须与所选基和值的数量严格匹配；Hybrid 运算使用多项式长度。
- Converter workspace 和 scratch buffer 应在热循环外创建并复用。调用方提供输出和 workspace 后，批量 API 不会在内部执行分配。
- 并非所有底层运算都在 release 模式验证这些条件，调用方须维持方法的文档契约。

## SIMD feature

可选的 `simd` feature 启用 portable-SIMD 小值和模算术路径。该 feature 默认 关闭，并且需要 nightly Rust 工具链。

## 测试与 benchmark

```text
cargo test -p primus_rns
cargo bench -p primus_rns --bench decompose
```

## 许可证

本 crate 可由你选择使用 [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) 或 [MIT License](../../LICENSE-MIT)。
