# primus_decompose

[English](README.md) | 简体中文

`primus_decompose` 为 [Primus FHE](../../README.zh_CN.md) 提供近似有符号 radix 分解。 它将可复用的 basis 预计算与单值、批量 digit 提取分开，用于 gadget product 和 key switching。

> [!WARNING]
> 本 crate 属于实验性的 Primus FHE workspace。其 API、表示与数值契约可能发生 不兼容修改。

## 核心类型

| 类型 | 职责 |
| --- | --- |
| `DecompositionBaseLog` / `DecompositionLevelCount` | 经过检查的基数对数和正的保留层数 |
| `DecompositionConfig` | 基数和保留层数；`ApproxSignedBasis::try_from((config, modulus))` 绑定模数 |
| `primitive::ApproxSignedBasis<T>` | 单 limb 输入，使用显式模数或隐式 native 模数 `2^T::BITS` |
| `big_integer::BigUintApproxSignedBasis<T>` | 定宽、多 limb 输入，使用显式整数模数 |
| `OnceSignedDecomposer`、`OnceBigUintSignedDecomposer` | 提取一个保留层，由对应 basis 的 `decomposer_iter()` 返回 |
| `ApproxSignedBasisError` | `try_new` 和 `TryFrom` 返回的构造参数错误 |

`T: FheUint` 在 primitive basis 中是无符号系数类型，在 BigUint basis 中是 limb 类型。 `BigUint` 来自 [`primus_integer`](../primus_integer/README.zh_CN.md)，不是动态扩容的 大整数库。应一次构造并复用 basis。

## 数学契约

设 `B = 2^log_basis`、`L = level_count()`、`d = drop_bits()`，分解的 signed digit 及其权重满足：

```text
-B/2 <= digit_i < B/2
weight_i = 2^d * B^i                  (0 <= i < L)
reconstructed = sum(digit_i * weight_i) mod modulus
```

`decomposer_iter()` 和 `scalar_iter()` 都从最低保留层迭代到最高层。输入与重组结果之间的模环距离不超过 `approximate_error_bound()`：`d == 0` 时为零，否则为 `2^(d - 1)`。

初始化负责选择内部代表元并计算初始舍入 carry。被丢弃的位按最近值舍入，在该代表元中 恰好位于中点时向上舍入。特别是，native 输入的重组结果为 `round_half_up(input / 2^d) * 2^d` 模 `2^T::BITS`。对于其他模数，不能用直接舍入 canonical 输入替代初始化：代表元调整属于正确性前提。

输出的编码取决于具体操作：

| 操作 | 数学 digit `z` 的编码 |
| --- | --- |
| Primitive `decompose*` | 单个模 `q` 的 canonical residue；负 `z` 编码为 `q + z`，native 模数下使用相应 wrapping 表示 |
| BigUint `decompose_slice_to` | 模 `Q` 的全宽 canonical residue；负 `z` 编码为 `Q + z` |
| BigUint `decompose_radix*` | 单 limb 的 `[0, B)` 值，编码 `z mod B`；`u >= B/2` 应解读为 `u - B` |

`decompose_radix*` 表示 **signed digit** 模 radix 的编码。例如 `B = 256` 时，输出 `255` 表示 `-1`，不是正数 `255`。提升到其他模数前，应先按中心值解释该 digit。

## 构造与保留层数

`DecompositionBaseLog` 检查 `log_basis >= 2`；`DecompositionLevelCount` 检查 `L >= 1`。通过 `new`、`try_new` 或 `TryFrom` 构造，用 `.get()` 读取整数。它们不添加固定上限。Basis 构造器及 `log_basis()` / `level_count()` 访问器使用这两个类型。

两种 basis 还要求 `log_basis < T::BITS`、模数不小于 `B`，并且保留层数适合分解位宽。多 limb basis 的层数可以大于一个 limb 的位数。对这些配对错误，basis 的 `new` 会 panic，`try_new` 返回 `ApproxSignedBasisError`。

`DecompositionConfig { log_basis, level_count }` 将分解选择与模数分开。 `ApproxSignedBasis::<u32>::try_from((config, None))` 准备 native basis，`ApproxSignedBasis::try_from((config, Some(q)))` 使用显式模数。Config 保存选择，不持有预计算存储。

不同表示的分解位宽 `m` 定义如下：

| Basis 与模数 | 位宽 `m` |
| --- | --- |
| Primitive，`None` | `T::BITS`，隐式模数为 `2^T::BITS` |
| Primitive，显式二次幂模数 `q` | `log2(q)` |
| Primitive，其他显式模数 `q` | `bit_width(q)` |
| BigUint，任意显式模数 `Q` | `bit_width(Q)`，**包括二次幂模数** |

完整层数为 `floor(m / log_basis)`。构造参数 `level_count` 表示可选的**保留层数**：`Some(L)` 要求 `1 <= L <= full_level_count`，`None` 使用全部完整层。两种情况下都有 `drop_bits = m - L * log_basis`，因此当 `m` 不能被 `log_basis` 整除时，即使传入 `None` 也会丢弃低位。

BigUint 模数必须是非空、little-endian 的 limb slice，最高 limb 不能为零。Basis 拥有模数的一份副本。每个输入都必须使用与模数相同的 limb 数，即使输入值较小，也要 保留高位的零 limb。

## Primitive 工作流

对一批输入初始化一次，然后让同一份 adjusted values 和不断更新的 carry 缓冲区依次 经过所有层。每层输出会被下一层覆盖，应先消费当前结果：

```rust
use primus_decompose::{DecompositionBaseLog, primitive::ApproxSignedBasis};

let basis = ApproxSignedBasis::new(Some(97_u32), DecompositionBaseLog::new(2), None);
let values = [42_u32, 96];
let mut adjusted = [0_u32; 2];
let mut carries = [false; 2];
let mut digits = [0_u32; 2];
let mut reconstructed = [0_u32; 2];

basis.init_value_carry_slice_to(&values, &mut adjusted, &mut carries);
for (decomposer, weight) in basis.decomposer_iter().zip(basis.scalar_iter()) {
    decomposer.decompose_slice_to(&adjusted, &mut digits, &mut carries);
    // 本例参数较小，中间乘积不会超出 u32。
    for (sum, &digit) in reconstructed.iter_mut().zip(&digits) {
        *sum = (*sum + digit * weight) % 97;
    }
}

assert_eq!(basis.drop_bits(), 1);
assert_eq!(reconstructed, [42, 0]); // 模 97 的环距离分别为 0 和 1。
```

Primitive 二次幂模数的输入不需要 adjusted-value 缓冲区：用 `init_carry_slice` 初始化，再将原始输入依次传给每层。它对非二次幂模数会 panic，此时应使用 `init_value_carry_slice_to`。单值处理使用 `init_value_carry`，再调用 `decompose`，同样逐层传递 carry。完整契约见 [primitive basis API](src/primitive/basis.rs)。

## BigUint 工作流与布局

对于 `N` 个值、每个值 `W = big_uint_value_len()` 个 limb，全宽缓冲区有 `N * W` 个 limb，采用 **value-major** 布局，每个值内部为 little-endian：

```text
[value_0_low, ..., value_0_high, value_1_low, ..., value_1_high, ...]
```

Carry 缓冲区有 `N` 个布尔值。全宽 digit 输出有 `N * W` 个 limb；紧凑的 `decompose_radix_slice_to` 输出只有 `N` 个 limb。即使 `Q` 是二次幂，BigUint 版本也必须执行输入初始化。

使用 `init_value_carry_slice_to` 和 `decomposer_iter()`，遵循相同的升序逐层 carry 协议。单值也使用相同的批量接口，提供一个全宽 value 缓冲区和一个元素的 carry slice。精确缓冲区契约见 [BigUint basis API](src/big_integer/basis.rs) 和 [digit 输出 API](src/big_integer/common.rs)。

RNS/CRT residue 使用 modulus-major 存储，不是这里的 value-major limb 布局。整数分解前，使用 [`primus_rns`](../primus_rns/README.zh_CN.md) 完成转换。

## 调用方契约与分配

- 原始输入必须为 canonical 值：位于 `[0, q)` 或 `[0, Q)`。Primitive native 模数允许系数类型的任意位模式。这些方法不会对输入做模约简。
- Adjusted inputs 是内部位表示，不保证是 canonical residue。整个分解过程应保持 它们不变，不能再做模约简。
- 按层数升序应用每个 operator，不能跳层或重置 carry。Digit 为零时也可能有 carry。 新的一批输入必须重新初始化，不能复用上一批输入的最终 carry 值。
- Primitive 的输入、输出和 carry slice 必须等长；BigUint 必须满足上述精确形状。 Slice 方法在 release 模式不验证这些布局。
- Slice 方法覆盖输出并更新 carry，不会累加 digit。BigUint 的 `init_value_carry_slice_assign` 还会覆盖原始输入。
- 构造器会分配预计算存储。分解和 slice 初始化复用调用方的缓冲区，内部不分配。BigUint 的 `approximate_error_bound` 为精度诊断分配结果。

## Feature 与进一步阅读

默认 feature 集为空。可选的 `simd` feature 转发到 `primus_integer/simd`，需要 nightly Rust；它不选择独立的分解 backend。普通循环也可以受益于编译器自动向量化。

公开契约见 [rustdoc 对应源码](src)；工作负载和运行命令见[基准指南](benches/README.zh_CN.md)，workspace 验证入口见[测试指南](../../guides/development/testing.md)。

## 许可证

可任选 [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) 或 [MIT License](../../LICENSE-MIT)。
