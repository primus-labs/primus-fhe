# primus_fft

[English](README.md) | 简体中文

`primus_fft` 为 `Z[X] / (X^N + 1)` 中的多项式提供负循环 Fourier 变换。它在 RustFFT 和 `tfhe-fft` 之上提供统一的 table 与 workspace API，并实现 [Primus FHE](../../README.zh_CN.md) 的 Fourier FHE 路径所需的 torus 转换。

> [!WARNING]
> 本 crate 属于实验性的 Primus FHE workspace。其 API、Fourier 表示和数值契约 尚不稳定，可能随时发生不兼容修改。

## 核心类型

| 类型 | 职责 |
| --- | --- |
| `FftTable` | 针对一个多项式长度定义的后端无关负循环变换契约 |
| `RustFftTable` | 基于 RustFFT 的 `FftTable` 实现 |
| `TfheFftTable` | 基于 unordered `tfhe-fft` plan 的 `FftTable` 实现 |
| `FftEngine<'a, Table>` | 一个不可变 table 引用以及一份可复用的可变 workspace |
| `TorusFftValue` | 在无符号 `u16`、`u32` 或 `u64` torus 位模式与 `f64` 之间转换 |

对于 `N = 2^log_n`，变换将 `N` 个系数映射为 `N / 2` 个复数值。Table 只需构造一次，重复变换时复用 engine。

## Features

默认不启用具体 FFT 引擎。`FftTable`、`FftEngine`、`Complex64` 和 `TorusFftValue` 始终可用。

- `rustfft` 导出 `RustFftTable` / `RustFftWorkspace`。
- `tfhe-fft` 导出 `TfheFftTable` / `TfheFftWorkspace`。

两者可以同时启用。依赖声明显式选择，例如 `primus_fft = { path = "../primus_fft", features = ["rustfft"] }`；未选择引擎时仍可实现自己的 `FftTable`。下方示例使用 `rustfft`。

## 示例

```rust
use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable};
use primus_shape::PolyLength;

let table = RustFftTable::new(PolyLength::new(32)); // N = 32
let mut fft = FftEngine::new(&table);
let input: Vec<u32> = (0..fft.poly_length().get()).map(|value| value as u32).collect();
let mut fourier = vec![Complex64::default(); fft.fourier_length()];
let mut output = vec![0u32; fft.poly_length().get()];

fft.forward_as_torus(&input, &mut fourier);
fft.backward_as_torus(&fourier, &mut output);

assert_eq!(output, input);
```

## 变换形式

- `forward_as_torus` 将每个无符号整数重新解释为有符号位模式，再乘以 `2^-BITS`；例如 `u32::MAX` 表示 `-1 / 2^32`。
- `forward_as_integer` 执行相同的有符号位模式解释，但不做 torus 缩放。它适合 secret key、分解 digit 等小整数多项式。
- `backward_as_torus` 执行逆变换、torus 反向缩放、舍入以及到无符号字长的 wrapping 转换。

负循环卷积应对 torus 多项式调用 `forward_as_torus`，对整数多项式调用 `forward_as_integer`，逐点执行复数乘法，再调用 `backward_as_torus`。

## Table 与 workspace 契约

Fourier 值和工作区必须来自**同一个 table 实例**。独立构造的 table 即使后端和长度相同也不能互换。长度或容量检查不验证此身份，调用方须保留来源关系。

Table 不可变并实现 `Send + Sync`，可在线程间共享；每个并发 worker 使用独立的 `FftEngine` 或 `new_workspace()` 结果。输入和输出接受普通 slice，包括子切片，无需额外对齐。

输入和输出长度必须精确匹配，否则变换会 panic：

- 系数 slice 包含 `poly_length().get()` 个值；
- Fourier slice 包含 `fourier_length() == poly_length().fourier_poly_len()` 个值。

推荐使用 `FftEngine::new(table)`，并保留 engine 以重复执行变换。完整方法契约见 [table 与 engine API](src/table.rs)。

内置工作区在析构时擦除缓冲区；`fft.zeroize_workspace()` 可擦除并保留分配。变换不会在每次调用后擦除 scratch。调用方持有的输入/输出、寄存器和栈副本不在此缓冲区保证内，自定义后端自行定义擦除行为。

`FftTable::automorphism_map(degree)` 为 `[1, 2N)` 内的奇数 `degree` 分配可复用的 `X -> X^degree` 映射，第 `j` 项给出输出 `j` 对应的 `(source, conjugate)`。映射须沿用原 table 的 Fourier 顺序；单独应用它不执行密码学 key switching。

## 长度与精度

`FftTable::new` 接收 [`primus_shape::PolyLength`](../primus_shape/README.zh_CN.md#多项式长度)。Table 和 engine 的 `poly_length()` 返回此类型，`fourier_length()` 返回复数元素数量。构造包含 planning 和分配，应放在重复变换路径之外。

变换使用 `f64`，属于近似计算，不保证整字宽 torus 输入逐位往返一致。正确舍入取决于累积浮点误差和整数操作数大小，外层算法须维持合适的精度预算。转换与舍入规则见 [torus API](src/torus.rs)。

## 测试与 benchmark

```text
cargo test -p primus_fft --features rustfft,tfhe-fft
cargo bench -p primus_fft --bench fft --features rustfft,tfhe-fft
```

## 许可证

本 crate 可由你选择使用 [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) 或 [MIT License](../../LICENSE-MIT)。
