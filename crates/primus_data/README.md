# primus_data

English | [简体中文](README.zh_CN.md)

`primus_data` provides small traits for writing algorithms over contiguous storage without tying them to one owning container.

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API is unstable and may change incompatibly at any time.

## Overview

The crate separates four storage capabilities:

- `RawData` associates a backend with its element type;
- `Data` provides immutable slice access;
- `DataMut` adds mutable slice operations;
- `DataOwned` adds construction from a slice or a `Vec` for owning backends.

This lets arithmetic and cryptographic kernels accept borrowed slices, arrays, or owned buffers through one explicit contiguous-storage contract.

| Backend | `Data` | `DataMut` | `DataOwned` |
| --- | :---: | :---: | :---: |
| `&[T]` | yes | no | no |
| `&mut [T]` | yes | yes | no |
| `[T; N]` | yes | yes | no |
| `&[T; N]` | yes | no | no |
| `&mut [T; N]` | yes | yes | no |
| `Vec<T>` | yes | yes | yes |
| `Box<[T]>` | yes | yes | yes |
| `Arc<[T]>` | yes | no | no |
| `AVec<T, A>` and `ABox<[T], A>` | yes | yes | no |

References to a supported backend forward its capabilities: `&S` supports reading, and `&mut S` supports mutation when `S` does.

The aligned backends require the optional `aligned-vec` feature. Their alignment is chosen explicitly during allocation; they do not implement `DataOwned`.

## Example

```rust
use primus_data::Data;

fn sum<D: Data<Elem = u64>>(data: &D) -> u64 {
    data.iter().copied().sum()
}

assert_eq!(sum(&[1, 2, 3, 4]), 10);
assert_eq!(sum(&vec![1, 2, 3, 4]), 10);
```

`primus_data` intentionally models contiguous buffers only. It does not hide allocation, alignment selection, or higher-level layout invariants from the calling algorithm.

## License

Licensed under either the [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) or the [MIT License](../../LICENSE-MIT), at your option.
