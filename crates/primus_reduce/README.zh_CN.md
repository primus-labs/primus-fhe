# primus_reduce

[English](README.md) | 简体中文

`primus_reduce` 定义 Primus FHE 中模数实现与上层算法共享的模算术契约。

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

## 概览

从 [prelude](src/prelude.rs) 导入运算 trait，并使用
[`primus_modulus`](../primus_modulus/README.zh_CN.md) 的具体模数。Trait 涵盖
规范、惰性、切片、有符号和融合运算。`RingContext` 和 `FieldContext` 描述
支持的运算集合。算法所需的素性或可逆性须单独确认。

## 示例

```rust
use primus_modulus::BarrettModulus;
use primus_reduce::prelude::*;

let modulus = BarrettModulus::new(97u64);

assert_eq!(modulus.reduce_add(80, 30), 13);
assert_eq!(modulus.reduce_mul(12, 9), 11);

let mut values = [80, 30];
let rhs = [30, 80];
modulus.reduce_add_slice_assign(&mut values, &rhs);
assert_eq!(values, [13, 13]);
```

## 调用方契约

按方法契约传入规范剩余类和完整缓冲区。惰性运算的结果经单次约简后可作为
规范剩余类使用。输入范围、长度检查及可失败的求逆入口见
[标量 trait](src/ops.rs)和[切片 trait](src/slice_ops.rs)。

## 有符号系数

[`EncodeSigned<T>`](src/signed.rs) 将有符号系数提升为规范剩余类，无明文缩放。
显式模数 `q` 要求系数幅度严格小于 `q`，原生模数可表示所有有符号值。
`ReduceDotProductSigned<T>` 沿用同一有符号输入契约，可直接计算点积并省去编码副本。

```rust
use primus_modulus::{NativeModulus, UintModulus};
use primus_reduce::prelude::*;

assert_eq!(UintModulus::new(97u64).encode_signed(-1), 96);
assert_eq!(NativeModulus::<u64>::new().encode_signed(-1), u64::MAX);
let mut output = [0u64; 3];
UintModulus::new(97).encode_signed_slice_to(&[-1, 0, 1], &mut output);
assert_eq!(output, [96, 0, 1]);
```

## 预备模切

通过 [`PrepareModulusSwitch` 或 `ModulusSwitch::new`](src/modulus_switch.rs)
准备一对源模数和目标模数。`switch` 对规范源剩余类计算
`value * target / source` 的最近整数，平局向上，目标端点回绕到零。
两端模数均至少为二，且均支持原生模数。`switch_map` 可为每个剩余类携带附属数据，
省去中间缓冲。批量调用 panic 时，已经执行的回调效果仍然保留。
参见 [primus_modulus 的示例](../primus_modulus/README.zh_CN.md#预备模切)。

## 许可证

本 crate 可由你选择使用 [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) 或 [MIT License](../../LICENSE-MIT)。
