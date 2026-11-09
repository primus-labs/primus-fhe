# primus_ntt

[English](README.md) | 简体中文

`primus_ntt` 为 `Z_q[X] / (X^N + 1)` 中的多项式提供原地负循环数论变换。它包含 通用无符号整数 table、优化的 `u32` 和 `u64` table、直接 monomial 变换，以及 [Primus FHE](../../README.zh_CN.md) 使用的 modulus-major DCRT 变换。

> [!WARNING]
> 本 crate 属于实验性的 Primus FHE workspace。其 API、NTT 表示、数值契约和 backend 选择尚不稳定，可能随时发生不兼容修改。

## 核心类型

| 类型 | 职责 |
| --- | --- |
| `NttTable` | 通用构造及正向/逆向变换契约 |
| `MonomialNttTable` | 无需构造系数多项式，直接变换 `coeff * X^degree` |
| `UintNttTable<T>` | 使用 Shoup 乘法的通用无符号整数实现 |
| `U32NttTable` | 针对小于 `2^30` 的 `u32` 模数优化的 table |
| `U64NttTable` | 针对小于 `2^62` 的 `u64` 模数优化的 table |
| `DcrtTable<Ntt>` | 为每个 CRT 模数保存一个相同长度的 NTT table |
| `U32DcrtTable`、`U64DcrtTable`、`UintDcrtTable<T>` | 常用 DCRT 别名 |

变换原地执行，每次调用不分配 scratch；应为各环和模数构造并复用 table。

## 示例

```rust
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable};
use primus_shape::PolyLength;

let modulus = BarrettModulus::new(193_u32);
let table = U32NttTable::new(PolyLength::new(32), modulus).unwrap(); // N = 32；2N 整除 193 - 1
let expected: Vec<u32> = (0..table.poly_length().get()).map(|i| i as u32).collect();
let mut values = expected.clone();

table.transform_slice(&mut values);
// `values` 现在以 bit-reversed 顺序保存 NTT 求值。
table.inverse_transform_slice(&mut values);

assert_eq!(values, expected);
```

Table 不可变并实现 `Send + Sync`，可在线程间共享，各线程使用独立缓冲区。克隆 `U32NttTable` 或 `U64NttTable` 会复制预计算存储，重复计算时应优先共享 table。

`NttAutomorphismPermutation::new(degree, poly_length)` 为 `[1, 2N)` 内的奇数 `degree` 准备 bit-reversed 顺序下的 `X -> X^degree` 映射。`apply_to` 接收各含 `N` 个点值的输入和输出，保持 residue 范围。DCRT 各分量可独立应用同一映射；同态使用仍需方案层的 key switching。完整契约见[自同构 API](src/automorphism.rs)。

## 表示与取值范围

对于 `N = 2^log_n`，正向变换读取按幂次升序排列的系数，生成 bit-reversed 顺序的求值；逆向变换读取这种 bit-reversed 表示，包含乘以长度逆元的归一化，并恢复按幂次升序排列的系数。

每个单模数输入或输出 slice 都必须恰好包含 `table.poly_length().get()` 个值，长度不匹配会 panic。不同 table 的点值只有在根、顺序和归一化一致时才能互换，不能仅凭长度和模数相同判断兼容。

| 操作 | 输入范围 | 输出范围 |
| --- | --- | --- |
| `transform_slice` | `[0, q)` | `[0, q)` |
| `inverse_transform_slice` | `[0, q)` | `[0, q)` |
| `lazy_transform_slice` | `[0, 4q)` | `[0, 4q)` |
| `lazy_inverse_transform_slice` | `[0, 2q)` | `[0, 2q)` |

Lazy 值表示模 `q` 的剩余类，但其更宽的整数范围属于调用契约。特别是，lazy forward 的结果不一定能直接作为 lazy inverse 的输入；调用 inverse 前应先将其 规范化到对应方法接受的范围。

变换操作接收 mutable slice。使用 [`primus_poly`](../primus_poly/README.zh_CN.md) wrapper 时，借用其存储执行变换，再将同一存储包装为结果的表示类型。

## 构造约束

- 构造器接收 [`primus_shape::PolyLength`](../primus_shape/README.zh_CN.md#多项式长度)；`poly_length()` 返回同一类型。
- 模数必须为素数且存在本原 `2N` 次单位根，要求 `2N` 整除 `q - 1`。素性由调用方保证，构造器和 `FieldContext` 均不证明素性。
- `UintNttTable<T>` 要求 `1 < q < 2^(T::BITS - 2)`；`U32NttTable` 要求 `q < 2^30`，`U64NttTable` 要求 `q < 2^62`。预留的两个高位保证小于 `4q` 的 lazy 值可表示。
- 通用 table 还要求根的阶 `2N` 能由 `T` 表示，且 `N < q`。

`NttTable::new` 搜索本原根并准备可复用 table。构造错误与精确条件见 [NTT API](src/ntt/mod.rs)。

## Monomial 变换

`MonomialNttTable` 将 `coeff * X^degree` 的 NTT 表示直接写入长度严格匹配的输出 slice。Degree 按模 `2N` 解释，与负循环环中的 `X^N = -1` 一致。

`transform_monomial` 要求 `coeff` 是 canonical residue，即 `0 <= coeff < q`；该方法不会约简或验证系数。常见的 `X^degree` 和 `-X^degree` 情形应分别使用 `transform_coeff_one_monomial` 和 `transform_coeff_minus_one_monomial`。

自定义 `MonomialNttTable` 实现须提供文档规定的根值与排列。默认 monomial 方法在写入输出前检查实际使用的根数组的精确长度；直接填充路径不读取根数组。根值与排列不作运行时验证，完整契约见 [monomial API](src/ntt/mod.rs)。

## DCRT 布局

`DcrtTable` 要求模数列表非空，所有分量使用同一个 `PolyLength`。`poly_length()` 返回环长度，`rns_poly_len()` 返回总元素数 `moduli_count * N`，后者须能由 `usize` 表示。系数和变换 slice 按 table 的模数顺序采用 modulus-major 布局：

```text
[a_0 mod q_0, ..., a_(N-1) mod q_0,
 a_0 mod q_1, ..., a_(N-1) mod q_1,
 ...]
```

这与 [`primus_poly`](../primus_poly/README.zh_CN.md) 中 `CrtPolynomial` 和 `DcrtPolynomial` 的布局一致。DCRT 调用方须维持精确总长度、模数顺序、系数范围与各分量的变换约定，总长度检查仅作 debug 诊断。完整契约见 [DCRT API](src/dcrt/mod.rs)。

`DcrtTable` 提供完整多项式的正逆变换，以及作用于所有分量的 `transform_coeff_one_monomial`。通过 `iter()` 或 `ntt_tables()` 访问分量 table，可使用各自的 lazy 和一般 monomial 操作。

## SIMD backend 与编译目标

默认 feature 集为空。专用 x86-64 table 在运行时选择可用的 scalar 或 SIMD 内核，无需启用可选的 `simd` feature；其他架构使用 scalar 实现。`simd` feature 启用依赖中的 portable-SIMD 支持，需要 nightly Rust。

仓库[编译配置](../../.cargo/config.toml) 使用 `target-cpu=native`。构建可移植二进制时须覆盖其 rustflags；仅有运行时分派不能使面向本机编译的产物可移植。

## 测试与 benchmark

```text
cargo test -p primus_ntt
cargo bench -p primus_ntt --bench bench_ntt
```

## 许可证

本 crate 可由你选择使用 [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) 或 [MIT License](../../LICENSE-MIT)。
