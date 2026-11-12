# primus_modulus

[English](README.md) | 简体中文

`primus_modulus` 提供具体的模数 context 和算术内核，实现 [`primus_reduce`](../primus_reduce/README.zh_CN.md) 定义的契约。

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

## 模数类型

| 类型 | 模数 | 适用场景 |
| --- | --- | --- |
| `NativeModulus<T>` | 隐式 `2^T::BITS` | 原生字长环上的 wrapping 算术 |
| `PowOf2Modulus<T>` | 大于一且可表示的二次幂 | 显式二次幂模数上的掩码算术 |
| `BarrettModulus<T>` | `1 < modulus < 2^(T::BITS - 2)` | 重复乘法、宽整数约简、融合切片运算和点积 |
| `CompactModulus<T>` | `1 < modulus < 2^(T::BITS - 2)` | 不保存预计算数据的基本加、减、取负和逆元运算 |
| `UintModulus<T>` | 任意可表示的 `modulus > 1` | 紧凑范围限制不适用时的基本算术 |

## 示例

```rust
use primus_modulus::{BarrettModulus, reduce::prelude::*};

let modulus = BarrettModulus::new(97u64);

assert_eq!(modulus.reduce_add(80, 30), 13);
assert_eq!(modulus.reduce_mul(12, 9), 11);

let lhs = [12, 20, 31];
let rhs = [9, 10, 11];
let mut output = [0; 3];
modulus.reduce_mul_slice_to(&lhs, &rhs, &mut output);
assert_eq!(output, [11, 6, 50]);
```

## 选择并构造模数

使用上述类型的构造器，或通过 [`ModulusConfig`](src/config.rs) 描述
Native、PowOf2 或 Barrett，再用 `M::try_from(config)` 准备模数。Barrett 的
`try_new` 检查范围，[`from_parts`](src/barrett/mod.rs) 接受已经验证的模数
及匹配的小端倒数。直接构造或修改 Compact 和 Uint 的公开字段时须维持各自的范围。

## 素数准备

用 [`is_prime_u64`](src/prime.rs) 验证公开 u64 参数的素性。NTT 兼容性和
密码学参数须单独核对。

## Feature

- `derive` 重新导出用于编译期常量模数的 `Barrett` derive 宏。参见 [`primus_barrett_derive`](../primus_barrett_derive/README.zh_CN.md)。
- `simd` 启用 nightly portable-SIMD 内核和切片调度；同时启用 `derive` 时，生成的 Barrett context 会使用相应 SIMD 路径。

两个 feature 默认都不启用。`simd` feature 需要 nightly Rust 工具链。

稳定版也可自动使用受支持的 x86_64 内核，未启用 `simd` 不代表只执行标量代码。标量与加速路径遵循相同的算术契约，性能取决于 CPU 和工作负载，运行入口见[基准指南](benches/README.md)。

## 算术契约

参见[运算契约](../primus_reduce/README.zh_CN.md#调用方契约)。
[`BarrettModulus`](src/barrett/mod.rs) 记录全字宽标量约简和允许操作数超过
目标模数的点积。`Native`、`PowOf2`、Barrett 及派生 Barrett 支持
[`ReduceDotProductSigned`](../primus_reduce/src/signed.rs)。

## 预备模切

五种模数及派生 Barrett 均实现共同的[模切契约](../primus_reduce/README.zh_CN.md#预备模切)。

```rust
use primus_modulus::{BarrettModulus, NativeModulus, reduce::PrepareModulusSwitch};

let conversion = BarrettModulus::new(97u32).prepare_switch_to(NativeModulus::new());
assert_eq!(conversion.switch(48), 2_125_344_641);
```

## 许可证

本 crate 可由你选择使用 [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) 或 [MIT License](../../LICENSE-MIT)。
