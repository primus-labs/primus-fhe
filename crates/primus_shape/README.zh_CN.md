# primus_shape

[English](README.md) | 简体中文

`primus_shape` 为 [Primus FHE](../../README.zh_CN.md) 的 FHE 布局和变换库提供
共用的、经过检查的多项式长度，不依赖多项式存储、算术、采样或变换实现。

> [!WARNING]
> 本 crate 属于实验性的 Primus FHE workspace。其 API 和支持的尺寸尚不稳定，
> 可能发生不兼容修改。

## 多项式长度

`PolyLength` 保存系数数量 `N`，要求为 `MIN_POLY_LENGTH..=MAX_POLY_LENGTH`
（目前为 `32..=2^17`）内的二次幂。构造一次后，在参数、尺寸、工作区和变换表
之间复用。`PolyLengthError` 保留被拒绝的长度。

```rust
use primus_shape::PolyLength;

let length = PolyLength::try_new(1024).unwrap();
assert_eq!(length.get(), 1024);
assert_eq!(length.log_n(), 10);
assert_eq!(length.fourier_poly_len(), 512);
```

`PolyLength::new` 在长度非法时 panic；`try_new` 和 `TryFrom<usize>` 返回错误。
`get()` 返回 `N`，`log_n()` 返回 `log2(N)`，`fourier_poly_len()` 返回 `N/2`
个复数元素。

长度合法并不证明模数、变换可用性及身份、residue 范围、完整缓冲区布局或密码学
安全级别成立。与其他数量相乘及分配空间仍需满足各自的溢出约束。

## 许可证

本 crate 可由你选择使用 [Apache License, Version 2.0](../../LICENSE-APACHE-2.0)
或 [MIT License](../../LICENSE-MIT)。
