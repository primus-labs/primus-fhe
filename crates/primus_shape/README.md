# primus_shape

English | [简体中文](README.zh_CN.md)

`primus_shape` provides checked polynomial lengths shared by FHE layouts and
transform libraries in [Primus FHE](../../README.md). It does not depend on
polynomial storage, arithmetic, sampling, or transform implementations.

> [!WARNING]
> This crate is part of the experimental Primus FHE workspace. Its API and
> supported dimensions are unstable and may change incompatibly.

## Polynomial length

`PolyLength` holds a coefficient count `N`, restricted to powers of two in
`MIN_POLY_LENGTH..=MAX_POLY_LENGTH` (currently `32..=2^17`). Construct it once
and reuse it across parameters, sizes, workspaces, and transform tables.
`PolyLengthError` retains the rejected length.

```rust
use primus_shape::PolyLength;

let length = PolyLength::try_new(1024).unwrap();
assert_eq!(length.get(), 1024);
assert_eq!(length.log_n(), 10);
assert_eq!(length.fourier_poly_len(), 512);
```

`PolyLength::new` panics on an invalid count; `try_new` and `TryFrom<usize>`
return an error. `get()` returns `N`, `log_n()` returns `log2(N)`, and
`fourier_poly_len()` returns `N/2` complex elements.

A valid length does not establish a modulus, transform availability or identity,
residue range, complete buffer layout, or cryptographic security level. Products
with other counts and allocation sizes retain their own overflow requirements.

## License

Licensed under either the [Apache License, Version 2.0](../../LICENSE-APACHE-2.0)
or the [MIT License](../../LICENSE-MIT), at your option.
