# primus_integer

[English](README.md) | 简体中文

`primus_integer` 定义 Primus FHE workspace 使用的整数 trait 和定宽多 limb 算术。

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。 其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

## 概览

主要 API 包括：

- `Integer`：汇集泛型内核所需的通用算术、位运算和转换能力；
- `SignedInteger` 和 `UnsignedInteger`：增加与符号相关的运算和相同位宽的伴随类型；
- 用于 checked、overflowing、wrapping、carrying、widening 和除法运算的细粒度 trait；
- `BigUint<S>`：基于借用或拥有所有权的小端 limb 存储的定宽无符号整数；
- 可选的默认宽度 portable SIMD 抽象。

## 示例

```rust
use primus_integer::{BigUint, UnsignedInteger};

fn significant_bits<T: UnsignedInteger>(value: T) -> u32 {
    value.bit_width()
}

assert_eq!(significant_bits(0x100u64), 9);

let value = BigUint(vec![u64::MAX, 1]);
assert_eq!(value.len(), 2);
assert_eq!(value.bit_width(), 65);
```

## `BigUint` 表示与调用方契约

`BigUint<S>` 是面向 FHE、RNS 和分解算法的底层定宽整数表示。它不是会自动增长的 通用大整数类型，也不是外部输入的校验边界。

limb 按小端顺序存储。limb 数量和前导零 limb 都属于表示和相等性的一部分：例如， `BigUint([1u64])` 和 `BigUint([1u64, 0])` 是不同的表示。

有效位宽使用 `u32`，limb 数和存储长度使用 `usize`。`checked_bit_width()` 忽略前导零 limb，对空值或零值返回 `Some(0)`，位宽超出 `u32::MAX` 时返回 `None`。`bit_width()` 返回相同位宽，但溢出时 panic。

调用方必须维持以下契约：

- 参与同一运算的所有输入、输出、累加器和模数具有相同的 limb 数量；
- 需要访问最低 limb 的运算接收非空存储；
- `left_shift_assign` 和 `right_shift_assign` 的 `bits` 参数小于 `T::BITS`； 这些方法执行单个 limb 宽度内的移位，而不是任意位数的整型移位；
- 传给模运算的操作数已经约简到 `[0, modulus)`。

这些前提不保证在 release 构建中被检查。各方法的完整契约见[公开 API](src/lib.rs)。

算术仍然是定宽的：各方法会按照文档返回 carry、borrow 或高位 limb，移位操作也会 按照各自契约返回或丢弃移出的位；这些方法不会扩展表示的长度。

`BigUint` 运算不是常量时间实现，不应假定其能够抵抗侧信道攻击。

## Serde feature

默认 feature 集为空。启用 `primus_integer/serde` 后，`BigUint<S>` 在存储 `S` 支持相应 serde trait 时可序列化和反序列化。包括 `Integer` 在内的算术 trait 不要求 serde，启用 feature 后也如此。泛型序列化代码需要自行声明 serde 约束。

序列化保留完整 limb 序列，包括高位的零 limb。反序列化恢复原始存储，不验证 limb 数、模数或算术域；它不是带版本的密钥或参数格式。

## SIMD feature

`simd` feature 启用 `SimdInteger`、`SimdArray` 及相关 trait。它使用 Rust 尚未稳定的 `portable_simd` API，因此需要 nightly。

默认向量类型根据目标 CPU feature 选择。`VECTOR_BITS` 使用 `u32`，数组长度 `LANE_COUNT` 使用 `usize`。泛型代码应使用关联类型 `SimdT`、`MaskT` 和 `Array`，而不应直接指定 lane 数量。

## 许可证

本 crate 可由你选择使用 [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) 或 [MIT License](../../LICENSE-MIT)。
