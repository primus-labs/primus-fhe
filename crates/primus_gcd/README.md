# primus_gcd

English | [简体中文](README.zh_CN.md)

`primus_gcd` provides allocation-free GCD, extended-GCD, and modular-inverse operations for Rust's primitive unsigned integer types.

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API is unstable and may change incompatibly at any time. The implementation is not documented as constant-time and must not be assumed to provide side-channel resistance.

## Supported operations

The `Xgcd` extension trait is implemented for `u8`, `u16`, `u32`, `u64`, `u128`, and `usize`. It provides:

- ordinary GCD and coprimality testing;
- unsigned extended-GCD coefficients satisfying `a * x - b * y = gcd(x, y)`;
- modular inversion for a general modulus;
- modular inversion modulo a power of two or the native wrapping modulus.

## Example

```rust
use primus_gcd::Xgcd;

assert_eq!(48u64.gcd(18), 6);

let (a, b, gcd) = u64::xgcd(240, 46);
assert_eq!(a as u128 * 240, b as u128 * 46 + gcd as u128);

let (inverse, gcd) = u64::gcdinv(17, 29);
assert_eq!(gcd, 1);
assert_eq!((inverse as u128 * 17) % 29, 1);
```

## Input contracts

- `xgcd(x, y)` requires `x >= y`.
- `gcdinv(x, modulus)` requires `x < modulus`.
- `gcdinv_pow_of_2(value, mask)` requires a nonzero mask of the form `2^k - 1`; only odd values are invertible.
- By convention, this crate defines `gcd(0, 0) = 0`.

See the [public API](src/lib.rs) for complete panic and result contracts. General extended-GCD routines follow FLINT's [`n_xgcd`](https://flintlib.org/doc/ulong_extras.html#c.n_xgcd) and [`n_gcdinv`](https://flintlib.org/doc/ulong_extras.html#c.n_gcdinv).

## License

Licensed under either the [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) or the [MIT License](../../LICENSE-MIT), at your option.
