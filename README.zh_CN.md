# Primus FHE

[English](README.md) | 简体中文

Primus FHE 是一个实验性的全同态加密 Rust workspace，API 仍在演进。

- [模运算](crates/primus_modulus)
- [负循环 NTT](crates/primus_ntt) 与 [Fourier 变换](crates/primus_fft)
- [剩余数系统](crates/primus_rns)
- [格密文布局和运算](crates/primus_lattice)
- [LWE](crates/primus_lwe)、[GLWE](crates/primus_glwe)、[RNS GLWE](crates/primus_glwe_rns) 与 [NTRU](crates/primus_ntru) 原语

在 workspace 根目录构建和测试。Cargo feature 决定启用的数据表示和计算后端。

```sh
cargo check --workspace --all-targets
cargo test --workspace
```
