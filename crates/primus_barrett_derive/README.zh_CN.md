# primus_barrett_derive

[English](README.md) | 简体中文

`primus_barrett_derive` 实现 [`primus_modulus`](../primus_modulus/README.zh_CN.md) 使用的 `Barrett` derive 宏，为编译期常量创建零尺寸模数 context。

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其生成 API 和数值契约尚不稳定，可能随时发生不兼容修改。

workspace 内的 crate 通常应启用 `primus_modulus` 的 `derive` feature，而不是直接依赖本过程宏 crate：

```toml
[dependencies]
primus_modulus = { path = "../primus_modulus", features = ["derive"] }
```

生成代码使用绝对路径 `::primus_modulus`，应保留该依赖名称；若在 Cargo 中重命名，需在 crate 根提供名为 `primus_modulus` 的别名。仅依赖 `primus_barrett_derive` 不会提供展开代码所引用的算术实现。

## 示例

```rust
use primus_modulus::{Barrett, reduce::prelude::*};

#[derive(Barrett)]
#[modulus(ty = u32, value = 536813569)]
struct Modulus;

assert_eq!(Modulus::value(), 536_813_569);
assert_eq!(Modulus.reduce_mul(12_345, 67_890), 301_288_481);
```

生成的 `value()` 和 `ratio()` 函数与 unit struct 使用相同的可见性。

## 输入契约

该宏只接受带有一个 `modulus` 属性的 unit struct：

```rust,ignore
#[derive(Barrett)]
#[modulus(ty = u64, value = 1125899906826241)]
pub struct CiphertextModulus;
```

- `ty` 必须是裸标识符 `u16`、`u32` 或 `u64`。
- 对应类型的 `value` 必须满足 `1 < value < 2^(BITS - 2)`。
- 无效的结构、类型、字面量和模数范围会产生编译期错误。

## 生成 API

生成的 unit struct 无需分配运行时 context，提供：

- 关联函数 `value()` 和 `ratio()`；
- `primus_reduce` 的标量、切片、惰性约简、逆元、幂运算、融合运算和点积实现。点积与运行时 Barrett 使用相同的输入界：每个操作数小于 `2^(BITS - 2)`，允许大于目标模数；
- 通过 `EncodeSigned` 转换有界 signed 系数；
- `Copy`、`Clone`、`PartialEq`、`Eq`、`Debug` 和 `Hash` 实现。

不要在同一个 struct 上再次 derive 这些标准 trait，否则会与宏生成的实现冲突。

## SIMD

同时启用 `primus_modulus` 的 `derive` 和 `simd` features，可使用需要 nightly 的 portable-SIMD 支持。稳定版也可使用受支持的原生内核，见[模数 features](../primus_modulus/README.zh_CN.md#feature)。

标量与 SIMD 展开遵循同样的 `BarrettModulus` 契约：调用方保证切片尺寸，惰性结果位于 `[0, 2*modulus)`，逆元操作要求输入可逆；编译期常量模数不保证素性。

## 许可证

本 crate 可由你选择使用 [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) 或 [MIT License](../../LICENSE-MIT)。
