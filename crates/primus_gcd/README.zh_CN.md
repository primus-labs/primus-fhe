# primus_gcd

[English](README.md) | 简体中文

`primus_gcd` 为 Rust 原生无符号整数类型提供无分配的 GCD、扩展 GCD 和模逆运算。

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。 其 API 尚不稳定，可能随时发生不兼容修改。 实现没有声明为常量时间，不应假定其能够抵抗侧信道攻击。

## 支持的运算

扩展 trait `Xgcd` 为 `u8`、`u16`、`u32`、`u64`、`u128` 和 `usize` 实现，提供：

- 普通 GCD 和互素性判断；
- 满足 `a * x - b * y = gcd(x, y)` 的无符号扩展 GCD 系数；
- 一般模数下的模逆；
- 以二的幂或原生 wrapping 模数为模的模逆。

## 示例

```rust
use primus_gcd::Xgcd;

assert_eq!(48u64.gcd(18), 6);

let (a, b, gcd) = u64::xgcd(240, 46);
assert_eq!(a as u128 * 240, b as u128 * 46 + gcd as u128);

let (inverse, gcd) = u64::gcdinv(17, 29);
assert_eq!(gcd, 1);
assert_eq!((inverse as u128 * 17) % 29, 1);
```

## 输入契约

- `xgcd(x, y)` 要求 `x >= y`。
- `gcdinv(x, modulus)` 要求 `x < modulus`。
- `gcdinv_pow_of_2(value, mask)` 要求 `mask` 非零且形如 `2^k - 1`；只有奇数可逆。
- 按照本 crate 的约定，`gcd(0, 0) = 0`。

完整的 panic 和结果契约见[公开 API](src/lib.rs)。一般扩展 GCD 例程基于 FLINT 的 [`n_xgcd`](https://flintlib.org/doc/ulong_extras.html#c.n_xgcd) 和 [`n_gcdinv`](https://flintlib.org/doc/ulong_extras.html#c.n_gcdinv)。

## 许可证

本 crate 可由你选择使用 [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) 或 [MIT License](../../LICENSE-MIT)。
