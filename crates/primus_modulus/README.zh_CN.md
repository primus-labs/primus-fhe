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

- 当溢出本身就表示对完整字长取模时，使用 `NativeModulus::new()`。
- 对可表示的二次幂模数使用 `PowOf2Modulus::new(value)`。
- 当受支持 Barrett 范围内的模数需要乘法和重复约简时，使用 `BarrettModulus::new(value)`。
- 对各自较小的基本运算集合使用 `CompactModulus::new(value)` 或 `UintModulus::new(value)`。

常量参数描述可使用 Native、PowOf2 或 Barrett 对应的 `ModulusConfig<M>`，再通过 `M::try_from(config)` 准备模数。转换检查所选表示及其范围，失败时返回 `ModulusConfigError`；它不验证素性或 NTT 兼容性。

带检查的构造器会验证文档规定的范围。直接构造或更新 `CompactModulus`、`UintModulus` 的 `.0` 字段时，必须保持该范围，算术方法通常不重新验证。Raw Barrett 构造器还要求正确的倒数；小端表示和精确范围见 [`BarrettModulus` 及 `from_parts`](src/barrett/mod.rs)。

## 素数准备

`is_prime_u64(value)` 对完整 u64 范围进行确定性素性判定，用于公开参数构造。
它不改变 reducer 构造器或 `FieldContext` 的契约：这些入口仍不证明素性。
素性本身也不证明 NTT 兼容性或密码学安全等级。

## Feature

- `derive` 重新导出用于编译期常量模数的 `Barrett` derive 宏。参见 [`primus_barrett_derive`](../primus_barrett_derive/README.zh_CN.md)。
- `simd` 启用 nightly portable-SIMD 内核和切片调度；同时启用 `derive` 时，生成的 Barrett context 会使用相应 SIMD 路径。

两个 feature 默认都不启用。`simd` feature 需要 nightly Rust 工具链。

稳定版也可自动使用受支持的 x86_64 内核，未启用 `simd` 不代表只执行标量代码。标量与加速路径遵循相同的算术契约，性能取决于 CPU 和工作负载，运行入口见[基准指南](benches/README.md)。

## 算术契约

运算 trait、输入范围、输出范围和切片长度要求均来自 `primus_reduce`。

- 规范运算通常要求规范剩余类输入，除非对应 trait 或具体实现明确允许更宽范围。Barrett 点积接受小于 `2^(T::BITS - 2)` 的操作数，包括来自其他 Barrett 模数、可能大于目标模数的 residue；切片与迭代器形式都返回规范剩余类。
- 惰性运算返回 `[0, 2 * modulus)` 中的代表元，在作为规范剩余类使用前需要再执行一次单次约简。
- 底层切片内核可能只用 `debug_assert*!` 诊断形状问题；release 调用方必须维持文档中的长度契约。
- `FieldContext` 是能力 marker；它不证明模数为素数，也不保证每个非零值都可逆。
- `EncodeSigned` 转换无符号幅度小于显式模数的系数；Native 接受所有 signed 值。切片转换检查输入与输出等长，不进行明文缩放。
- `ReduceDotProductSigned` 为 Native、PowOf2、Barrett 及派生 Barrett 组合有界 signed 系数与规范剩余类，检查两个切片等长，空输入返回零。

## 预备模切

五种模数及派生 Barrett 均实现 `primus_reduce::PrepareModulusSwitch`。一次构造 `source.prepare_switch_to(target)` 后复用其 `switch` 或 `switch_map` 方法，也可直接使用 `ModulusSwitch::new(source, target)`；两种方式遵循相同的[舍入和批量转换契约](../primus_reduce/README.zh_CN.md#预备模切)。

```rust
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_reduce::PrepareModulusSwitch;

let conversion = BarrettModulus::new(97u32).prepare_switch_to(NativeModulus::new());
let residue = conversion.switch(48);
```

## 许可证

本 crate 可由你选择使用 [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) 或 [MIT License](../../LICENSE-MIT)。
