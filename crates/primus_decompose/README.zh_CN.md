# primus_decompose

[English](README.md) | 简体中文

`primus_decompose` 为 [Primus FHE](../../README.zh_CN.md) 提供近似有符号 radix 分解。它将可复用的分解基预计算与单值、批量数位提取分开，用于 gadget product 和 key switching。

> [!WARNING]
> 本 crate 属于实验性的 Primus FHE workspace。其 API、表示与数值契约可能发生不兼容修改。

## 选择分解基

单 limb 输入使用 [primitive 分解基](src/primitive/basis.rs)，支持显式模数和
隐式原生模数 `2^T::BITS`。来自 [`primus_integer`](../primus_integer/README.zh_CN.md)
的定宽小端整数使用 [BigUint 分解基](src/big_integer/basis.rs)。分解基构造一次后可复用。

[参数类型](src/parameters.rs)记录经过检查的基数对数和正的保留层数。
`ApproxSignedBasis::try_from((config, modulus))` 将 `DecompositionConfig`
与模数绑定。分解基检查选择是否适合模数和 limb 位宽。即使保留全部完整层，
舍入时也可能丢弃低位。

## 数位与重组

基数 `B` 下的有符号数位位于 `[-B/2, B/2)`。分解器与权重均从最低保留层
开始迭代。加权和与原始剩余类的模环距离不超过 `approximate_error_bound()`。
通过分解基初始化输入以选择正确的代表元和初始进位。

| 输出 | 有符号数位的表示 |
| --- | --- |
| Primitive `decompose*` | 输入模数下的规范剩余类 |
| BigUint `decompose_slice_to` | 输入模数下的全宽规范剩余类 |
| BigUint `decompose_radix*` | 模 `B` 的单 limb。基数为 `256` 时，`255` 表示 `-1`。提升到其他模数前先按居中数位解释。 |

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

Primitive 二次幂模数可对原始输入使用 `init_carry_slice`，省去调整缓冲区。
其他模数使用 `init_value_carry_slice_to`。两者均按层数升序传递进位。

## BigUint 工作流与布局

BigUint 分解基始终需要初始化输入。批量缓冲按值排列，每个输入和全宽数位均占
`big_uint_value_len()` 个小端 limb。紧凑 radix 输出每个值占一个 limb。
完整契约见[分解基](src/big_integer/basis.rs)和[数位输出](src/big_integer/common.rs)。
对按模数排列的剩余类，先通过 [`primus_rns`](../primus_rns/README.zh_CN.md)
转换为整数，再分解。

## 调用方契约与 feature

传入规范剩余类和完整缓冲区。每批输入重新初始化，保留初始化输出，并通过同一
进位缓冲区依次处理所有层。切片运算覆盖数位输出并复用所提供的存储。
默认 feature 集为空。可选的 `simd` 转发到 `primus_integer/simd`，需要 nightly Rust。

参见[基准指南](benches/README.zh_CN.md)和 workspace [测试指南](../../guides/development/testing.md)。

## 许可证

可任选 [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) 或 [MIT License](../../LICENSE-MIT)。
