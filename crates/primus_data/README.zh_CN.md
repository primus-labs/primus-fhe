# primus_data

[English](README.md) | 简体中文

`primus_data` 提供一组小型 trait，使算法能够基于连续存储编写，而不必绑定到某一种拥有所有权的容器。

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。 其 API 尚不稳定，可能随时发生不兼容修改。

## 概览

本 crate 将连续存储能力分为四层：

- `RawData` 为存储后端关联元素类型；
- `Data` 提供不可变切片访问；
- `DataMut` 增加可变切片操作；
- `DataOwned` 为拥有所有权的存储后端增加从切片或 `Vec` 构造的能力。

算术和密码学内核因此可以通过一套明确的连续存储契约接收借用切片、数组或拥有所有权的缓冲区。

| 存储后端 | `Data` | `DataMut` | `DataOwned` |
| --- | :---: | :---: | :---: |
| `&[T]` | 是 | 否 | 否 |
| `&mut [T]` | 是 | 是 | 否 |
| `[T; N]` | 是 | 是 | 否 |
| `&[T; N]` | 是 | 否 | 否 |
| `&mut [T; N]` | 是 | 是 | 否 |
| `Vec<T>` | 是 | 是 | 是 |
| `Box<[T]>` | 是 | 是 | 是 |
| `Arc<[T]>` | 是 | 否 | 否 |
| `AVec<T, A>` 和 `ABox<[T], A>` | 是 | 是 | 否 |

受支持后端的引用转发其能力：`&S` 支持读取，`&mut S` 在 `S` 支持修改时也支持修改。

对齐存储后端需要启用可选的 `aligned-vec` feature。其分配需要显式选择对齐，因此未实现 `DataOwned`。

## 示例

```rust
use primus_data::Data;

fn sum<D: Data<Elem = u64>>(data: &D) -> u64 {
    data.iter().copied().sum()
}

assert_eq!(sum(&[1, 2, 3, 4]), 10);
assert_eq!(sum(&vec![1, 2, 3, 4]), 10);
```

`primus_data` 只对连续缓冲区建模，不会向调用算法隐藏分配、对齐选择或更高层的布局不变量。

## 许可证

本 crate 可由你选择使用 [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) 或 [MIT License](../../LICENSE-MIT)。
