# primus_reduce

[English](README.md) | 简体中文

`primus_reduce` 定义 Primus FHE 中模数实现与上层算法共享的模算术契约。

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

## 概览

本 crate 的 trait 将模数或约简上下文放在 receiver 位置：

```text
modulus.reduce_add(a, b)
modulus.reduce_mul_slice_to(a, b, output)
```

各运算被拆分为细粒度 trait，使模数类型只实现自身真正支持的标量、切片、惰性约简、逆元或融合运算。具体模数类型及其环算术内核位于 [`primus_modulus`](../primus_modulus)。本 crate 还提供不依赖具体模数类型的 `ModulusSwitch<T>` 执行器。

主要 API 分组如下：

- 用于规范算术、逆元、除法和幂运算的标量 `Reduce*` trait；
- 用于批量运算和 SIMD 调度的 `Reduce*Slice` trait；
- 结果位于 `[0, 2 * modulus)` 的 `LazyReduce*` trait；
- 描述模数元数据的 `Modulus` 和 `ExplicitModulus`；
- 能力 marker `RingContext` 和 `FieldContext`。

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

本 crate 定义接口，而不是输入校验边界。每个公开方法分别记录其输入范围、表示、输出状态和长度要求。

- 底层数值内核可能只通过 `debug_assert*!` 诊断形状不匹配；release 调用方必须维持文档中的契约。
- 点积在所有构建模式下都会显式检查两个切片等长。规范输入总是受支持；更宽的输入范围由具体实现规定。运行时和派生 Barrett 还接受小于 `2^(T::BITS - 2)` 的操作数，不要求它们小于目标模数。
- 惰性约简结果在被视为规范剩余类之前，需要再执行一次单次约简。
- 可失败逆元 trait 通过 `ReduceError` 报告错误；当所需逆元不存在时，不可失败的逆元和除法 trait 可能 panic。

`FieldContext` 表示某个模数类型实现了列出的运算集合。它不证明模数为素数，也不保证每个非零剩余类都可逆。调用方仍须验证自身算法所需的代数条件。

## 有符号系数

`EncodeSigned<T>` 将有界 signed 系数转换为规范剩余类，不进行明文缩放或通用模约简。可从 crate 根或 `prelude` 导入；自定义模数类型可以独立实现，不要求 `Reduce` 或 `ReduceNeg`。切片转换要求输入与输出等长。

`ReduceDotProductSigned<T>` 计算规范剩余类与有界 signed 系数的点积，不分配编码副本。它检查两个切片等长，返回规范剩余类，空输入返回零；signed 输入范围与 `EncodeSigned` 相同。支持情况见[模数类型](../primus_modulus/README.zh_CN.md#算术契约)。

`RingContext<T>` 包含这两个 signed 运算 trait，`FieldContext<T>` 通过 `RingContext<T>` 继承它们。两个 context 均要求 `T: FheUint`；只需要某个运算时可单独约束对应 trait。

```rust
use primus_modulus::{NativeModulus, UintModulus};
use primus_reduce::prelude::*;

assert_eq!(UintModulus::new(97u64).encode_signed(-1), 96);
assert_eq!(NativeModulus::<u64>::new().encode_signed(-1), u64::MAX);
let mut output = [0u64; 3];
UintModulus::new(97).encode_signed_slice_to(&[-1, 0, 1], &mut output);
assert_eq!(output, [96, 0, 1]);
```

显式模数 `q` 下，每个系数必须满足 `value.unsigned_abs() < q`，该前提不在 release 构建中检查。Native 模数接受所有 signed 值，包括 signed 最小值。导入的系数必须符合目标模数的范围，即使它们在另一个模数下有效。

## 预备模切

本 crate 导出 `PrepareModulusSwitch` 和 `ModulusSwitch<T>`。`source.prepare_switch_to(target)` 返回具体执行器，使用固有方法 `switch` 和 `switch_map`，不需要执行 trait。`ModulusSwitch::new(source, target)` 也可接受任意两个 `Modulus` 实现。

规范源剩余类映射为 `round(value * target / source) mod target`，中点向上舍入，目标端点回绕到零。两端都支持 Native 模数，显式模数必须至少为二。这是整数比例舍入，与模除法独立。

`RingContext` 包含准备能力，`FieldContext` 自然继承。只需要部分能力时可单独使用 `PrepareModulusSwitch`。具体实现及最小示例见 [`primus_modulus`](../primus_modulus/README.zh_CN.md#预备模切)；raw 倒数构造还须满足额外[正确性前提](src/modulus_switch.rs)。

`switch_map` 为每个系数携带附属数据，可完成输出转换或累加，无需中间缓冲区。迭代器或回调 panic 时，先前的效果不会回滚。

## 许可证

本 crate 可由你选择使用 [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) 或 [MIT License](../../LICENSE-MIT)。
