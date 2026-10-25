# primus_factor

[English](README.md) | 简体中文

`primus_factor` 提供预计算 factor，用于在固定模数下反复乘以固定值。预计算可以让标量、切片和可选 SIMD 乘法路径避免除法。

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

## Factor 类型

| 类型 | 预计算内容 | 适用场景 |
| --- | --- | --- |
| `ShoupFactor<T>` | `value` 和 `floor(value * 2^T::BITS / modulus)` | 通用的固定值标量与切片乘法 |
| `MultiplyFactor` | `u64` operand 和 `floor((operand << bit_shift) / modulus)` | 显式采用 32、52 或 64 位 shift 的专用 `u64` 内核 |
| `SimdShoupFactor<T>` | 每个 SIMD lane 各有一组 Shoup value 和 quotient | 启用 `simd` feature 时显式执行逐 lane SIMD 乘法 |

通常应选择 `ShoupFactor`。它支持标量乘法、原地和非原地切片乘法以及融合切片运算。`MultiplyFactor` 是更底层的构件，适用于已经将 shift 纳入数值契约的专用内核。

## 示例

```rust
use primus_factor::{FactorMul, FactorSliceOps, LazyFactorMul, ShoupFactor};

let modulus = 97u64;
let factor = ShoupFactor::new(12, modulus);

assert_eq!(factor.factor_mul_modulo(9, modulus), 11);

let lazy = factor.lazy_factor_mul_modulo(9, modulus);
assert!(lazy < 2 * modulus);
assert_eq!(lazy % modulus, 11);

let mut values = [9, 10, 11];
factor.factor_mul_slice_assign(&mut values, modulus);
assert_eq!(values, [11, 23, 35]);
```

标量运算使用 `FactorMul` / `LazyFactorMul`，切片使用 `FactorSliceOps` / `LazyFactorSliceOps`。`FactorBase` 提供构造，`Factor` 组合完整运算集合。

## 调用方契约

Factor 有意不保存模数。调用方必须在后续每次运算中传入构造或重置 factor 时使用的同一模数。

- `ShoupFactor<T>` 要求 `value < modulus` 且 `modulus < 2^(T::BITS - 1)`。
- `MultiplyFactor` 要求 operand 为规范剩余类，`bit_shift` 为 32、52 或 64，并且 `modulus < 2^(bit_shift - 2)`。乘法使用的 const `BIT_SHIFT` 必须等于构造时传入的 runtime `bit_shift`。
- 惰性运算返回 `[0, 2 * modulus)` 中的代表元；规范运算返回 `[0, modulus)` 中的值。
- 切片输入和累加器必须是规范剩余类。非原地和融合运算要求相关切片等长。
- 使用 raw 构造器时，value、quotient 和后续运算使用的 modulus 必须严格匹配。

部分底层契约只通过 `debug_assert*!` 诊断。release 调用方必须在进入重复算术内核前，于适当边界完成验证。

## SIMD feature

可选的 `simd` feature 需要 nightly，默认关闭。它启用 portable-SIMD 支持，并提供 `SimdShoupFactor` 和 `SimdFactorMul`，用于显式广播 factor 或逐 lane 打包。

稳定版也可在 x86-64 CPU 上加速受支持的 `u64` 切片，未启用 `simd` 不代表只执行标量代码，算术契约保持相同。标量与预计算 factor 的负载比较见[基准指南](benches/README.md)。

## 许可证

本 crate 可由你选择使用 [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) 或 [MIT License](../../LICENSE-MIT)。
