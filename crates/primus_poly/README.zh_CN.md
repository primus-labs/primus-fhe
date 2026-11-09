# primus_poly

[English](README.md) | 简体中文

`primus_poly` 为 [Primus FHE](../../README.zh_CN.md) 中使用的各种多项式表示提供存储 wrapper 和算术操作。它将系数、NTT、CRT/DCRT、多 limb 和 Fourier 数据明确区分，同时避免为每个多项式保存 context。

> [!WARNING]
> 本 crate 属于实验性的 Primus FHE workspace。其 API、数据表示和数值契约尚不稳定，可能随时发生不兼容修改。

## 数据表示

| 类型 | 表示与布局 | 主要操作 |
| --- | --- | --- |
| `Polynomial<S>` | 单个模数下按幂次递增排列的 `N` 个系数 | 加、减、取负、scalar/factor 乘法、负循环单项式、朴素乘法、求值和采样 |
| `NttPolynomial<S>` | 单个模数下的 `N` 个点值；顺序由 NTT context 定义 | 逐点算术、融合乘加和逆元 |
| `CrtPolynomial<S>` | modulus-major 系数数据：每个模数对应一个连续的 `N` 系数多项式 | 分量算术、scalar/factor 操作和负循环单项式 |
| `DcrtPolynomial<S>` | modulus-major NTT 数据：每个模数对应一个连续的 `N` 点变换结果 | 逐点算术、融合乘加、逆元和 factor butterfly 内核 |
| `BigUintPolynomial<S>` | coefficient-major 数据：每个系数是固定宽度的小端 limb 分块 | 多 limb 模加、模减和模取负 |
| `FourierPolynomial<S>` | 独立复数求值；顺序由 Fourier 后端定义 | 逐点加、减、取负、乘法、融合乘加和 scalar 乘法 |

`primus_poly` 负责保存数值并实现算术，不拥有变换表，也不替调用方选择表示。[`primus_ntt`](../primus_ntt) 负责系数与 NTT、CRT 与 DCRT 表示之间的转换；[`primus_fft`](../primus_fft) 提供 Fourier 变换。

平坦标量缓冲使用 slice 和 [`primus_reduce`](../primus_reduce/README.zh_CN.md)
的 `Reduce*Slice` trait，例如 `modulus.reduce_add_slice_assign(lhs, rhs)`。
多项式和密文 wrapper 保留各自表示的运算；DCRT 逆 butterfly 继续通过
`DcrtPolynomial::butterfly_mul_factor_to` 调用。

## 示例

```rust
use primus_modulus::CompactModulus;
use primus_poly::PolynomialOwned;

let modulus = CompactModulus::new(97_u64);
let mut lhs = PolynomialOwned::from_slice(&[80, 12, 5, 40]);
let rhs = PolynomialOwned::from_slice(&[30, 9, 96, 70]);

lhs.add_assign(&rhs, modulus);
assert_eq!(lhs.as_slice(), &[13, 21, 4, 13]);

// 在 Z_97[X]/(X^4 + 1) 中乘以 X。
lhs.mul_monomial_assign(1, modulus);
assert_eq!(lhs.as_slice(), &[84, 13, 21, 4]);
```

## 环多项式长度

FHE 布局和变换表使用 [`primus_shape::PolyLength`](../primus_shape/README.zh_CN.md#多项式长度)，表示经过检查的系数数量 `N`。Raw 多项式 wrapper 不另存环长度，元素数量仍为 `usize`。

Raw wrapper 使用 `len()` / `is_empty()` 查看完整存储：

| Wrapper | `len()` 统计的元素 | 一个完整多项式 |
| --- | --- | --- |
| `Polynomial` | 系数 | `N` |
| `NttPolynomial` | NTT 求值 | `N` |
| `FourierPolynomial` | 复数值 | `N/2` |
| `CrtPolynomial`、`DcrtPolynomial` | 全部模数下的 residue | `moduli_count * N` |

这些访问器不验证布局。Raw wrapper 可表示空、任意长度或 packed 存储；具体运算的契约决定其接受哪些布局。

## 存储与所有权

大多数多项式类型都对 backing store `S` 泛型化；`S` 实现 [`primus_data`](../primus_data/README.zh_CN.md) 提供的连续存储 trait。常用的系数、NTT 和 Fourier 表示提供了 `Vec` owned 别名与 slice borrowed 别名。CRT、DCRT 和多 limb wrapper 同样可以通过泛型类型构造在 owned 或 borrowed 存储之上。

`as_view()` 和 `as_mut_view()` 借用完整存储，保持多项式的表示类型。对应的 `From<&Wrapper<S>>` / `From<&mut Wrapper<S>>` 转换同样返回 slice wrapper，不复制元素。`into_inner()` 消耗 wrapper 并返回原存储，包括借用或对齐存储；它不分配，也不会将借用变为拥有型容器。

操作名称说明结果写入位置：

- `operation` 消耗一个支持修改的 wrapper，更新其存储后返回该 wrapper；
- `operation_assign` 原地更新 `self`；
- `operation_to` 将结果写入独立的输出 wrapper；
- `operation_rev_assign` 将交换操作数后的非交换运算写入可变操作数。

消耗以 `&mut [T]` 为 backing store 的 wrapper 仍会修改调用方的 slice。

## 布局与算术契约

这些 wrapper 有意不保存多项式长度、模数值、变换表、归一化状态或 limb 宽度。调用方必须在拥有相应契约的 FHE、RNS 或 transform 边界建立以下不变量，并在底层运算之间维持它们：

- 一起参与运算的所有输入和输出具有相同表示与布局；
- backing storage 能被传入的多项式长度或多 limb 系数宽度精确整除；
- CRT/DCRT 存储长度等于 `moduli.len() * poly_length`；按分量使用的 scalar、factor 和 modulus slice 均为每个分量提供一个元素，而 butterfly `w` 这类逐点 factor polynomial 与 backing storage 具有相同的 modulus-major 布局和长度；
- 数值满足所选 `primus_reduce` 或 `primus_factor` 操作要求的规范或惰性范围；
- 单项式指数位于对应文档规定的 `[0, 2N)` 范围内，需要二次幂 `N` 的方法收到满足条件的长度；
- NTT 和 Fourier 操作数由相互兼容的变换 context 产生。

Raw wrapper 不验证这些条件，调用方必须维持所选运算的契约。

`add_mul_monomial_pair_assign` 累加 `first * X^r + second * X^s`，其自由函数版本接受完整多项式组成的平坦批次。源系数和累加器须为规范 residue，多项式须等长且长度为二次幂，指数位于 `[0, 2N)`。

Barrett 域的 `lazy_add_mul_monomial_pair_assign` 和 `lazy_add_mul_monomial_assign` 则允许累加器位于 `[0, 2q)`，并保持此范围；源系数仍须规范化。将结果传给普通 NTT 等要求规范输入的运算前，用 `ReduceOnceSlice::reduce_once_slice_assign` 归一化。精确批量与范围契约见[单项式 API](src/monomial.rs)和 [lazy API](src/monomial/lazy.rs)。

`CoeffAutomorphismPermutation::new(d, poly_length)` 为 `[1, 2N)` 内的奇数 `d` 准备模 `X^N + 1` 的代换 `X -> X^d`。复用 `apply_to` 处理规范 residue，或用 `apply_signed_to` 处理所需取负均可表示的 signed 系数；两个缓冲区均须恰好包含 `N` 个系数。此置换不执行密码学 key switching，对应 NTT 置换位于 `primus_ntt`。完整契约见[自同构 API](src/automorphism.rs)。

## 随机采样

`Polynomial::random` 按模数收集 uniform residue；
`Polynomial::random_with_distribution` 从调用方选择的
`rand::distr::Distribution` 收集样本。两者均支持 `FromIterator` 存储，
要求 RNG 实现 `rand::Rng` 和 `rand::CryptoRng`。见[采样 API](src/poly/random.rs)。

专用分布采样、填充已有缓冲或累加噪声，使用
[`primus_distr`](../primus_distr/README.zh_CN.md) 中采样器的 slice API，
再将存储包装为相应多项式类型。非 uniform 分布应在系数域采样后再变换。
CRT 采样须将同一个逻辑系数样本编码到每个分量模数下；在各模数块中独立
采样 Gaussian 噪声会表示不同的值。

## 单项式算术基准

[monomial.rs](benches/monomial.rs) 对比模 `X^N + 1` 下 `acc += first * X^r + second * X^s` 的两次单项累加与一次配对累加。参数以基准源码为准；这些测量不代表 PBS/CBS 耗时。

```text
cargo bench -p primus_poly --bench monomial
```

## SIMD feature

可选的 `simd` feature 启用 portable-SIMD DCRT butterfly 路径以及算术依赖中相应的 SIMD 支持。该 feature 默认关闭，并且需要 nightly Rust 工具链。

## 许可证

本 crate 可由你选择使用 [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) 或 [MIT License](../../LICENSE-MIT)。
