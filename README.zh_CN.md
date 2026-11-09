# Primus FHE

[English](README.md) | 简体中文

Primus FHE 是实验性的 Rust 全同态加密 workspace，提供算术与格密文原语、LWE/GLWE/NTRU 加密，以及 GLWE NTT、GLWE Fourier 和 NTRU NTT 后端。

> [!WARNING]
> API、表示、算法和 crate 边界尚不稳定，可能直接发生不兼容修改。示例与基准参数用于功能演示，不构成安全性或失败概率推荐；项目尚未达到生产可用状态。

## 从这里开始

- **计算密文函数：** 从 [TFHE 操作与编码指南](crates/primus_tfhe/README.zh_CN.md) 选择 PBS、ManyLUT、MVB、CBS 或 Boolean 门，再选择下方后端。
- **直接使用加密原语：** 阅读 [LWE](crates/primus_lwe/README.zh_CN.md)、[GLWE](crates/primus_glwe/README.zh_CN.md)、[NTRU](crates/primus_ntru/README.zh_CN.md) 或 [RNS GLWE](crates/primus_glwe_rns/README.zh_CN.md)。
- **使用 BFV/BGV 系数或槽：** 从 [primus_bfv](crates/primus_bfv/README.zh_CN.md) 或 [primus_bgv](crates/primus_bgv/README.zh_CN.md) 的完整示例开始。
- **组合底层组件：** [库使用导航](guides/development/README.zh_CN.md) 介绍算术域、存储、迭代器、变换表示与工作区。

在仓库根目录运行一个完整的加密 → 查表 → 解密示例：

```sh
cargo run --release -p primus_tfhe_glwe_ntt --example ntt_basic
```

示例选择 `experimental` 操作配置，创建 context 和配套密钥，连续执行两次 PBS。源码区分 client 与 server，复用密钥、LUT、求值器和输出缓冲。各后端 README 提供其他操作的完整示例。

## TFHE 后端

| 家族 | NTT：显式素数环模数 | Fourier：原生字长环模数 |
| --- | --- | --- |
| [GLWE 参数与客户端](crates/primus_tfhe_glwe/README.zh_CN.md) | [GLWE NTT](crates/primus_tfhe_glwe_ntt/README.zh_CN.md) | [GLWE Fourier](crates/primus_tfhe_glwe_fourier/README.zh_CN.md) |
| [NTRU 参数与客户端](crates/primus_tfhe_ntru/README.zh_CN.md) | [NTRU NTT](crates/primus_tfhe_ntru_ntt/README.zh_CN.md) | — |

GLWE 支持两种 PBS 顺序。NTRU 使用独立的外部 LWE 秘密与环秘密，支持环模数 Q 到外部模数 q 的返回；可逆性要求针对环秘密，外部 binary/ternary 秘密没有奇数重量要求。Fourier 环目前只支持 `NativeModulus`，支持 RustFFT 与 TFHE-FFT；NTRU 的外部 q 可独立选择。

Classic 与 sparse 的操作覆盖见[能力表](crates/primus_tfhe/README.zh_CN.md#crate-分工与能力)。操作配置绑定消息模数和密钥域，context 准备相应客户端及 LUT 编译器；raw 密文不携带编码或秘密身份。

## Workspace 导航

| 层次 | Crate 与职责 |
| --- | --- |
| 存储与整数 | [primus_data](crates/primus_data/README.zh_CN.md)：连续存储；[primus_integer](crates/primus_integer/README.zh_CN.md)：整数 trait 与多 limb 算术；[primus_gcd](crates/primus_gcd/README.zh_CN.md)：GCD 与模逆 |
| 模算术 | [primus_reduce](crates/primus_reduce/README.zh_CN.md)：模数侧 trait；[primus_modulus](crates/primus_modulus/README.zh_CN.md)：模数实现；[primus_factor](crates/primus_factor/README.zh_CN.md)：乘法预计算；[primus_barrett_derive](crates/primus_barrett_derive/README.zh_CN.md)：常量 Barrett 模数 |
| 多项式与变换 | [primus_shape](crates/primus_shape/README.zh_CN.md)：经过检查的多项式长度；[primus_poly](crates/primus_poly/README.zh_CN.md)：多项式表示与算术；[primus_ntt](crates/primus_ntt/README.zh_CN.md)：精确变换；[primus_fft](crates/primus_fft/README.zh_CN.md)：Fourier 表与可复用 scratch |
| 分解与 RNS | [primus_decompose](crates/primus_decompose/README.zh_CN.md)：有符号 gadget 分解；[primus_rns](crates/primus_rns/README.zh_CN.md)：剩余类基、转换与 hybrid RNS |
| 采样与编码 | [primus_distr](crates/primus_distr/README.zh_CN.md)：私钥/噪声分布；[primus_encoding](crates/primus_encoding/README.zh_CN.md)：Rounded、Scaled、BFV RNS 系数编码与共享 batching |
| 密文表示 | [primus_lattice](crates/primus_lattice/README.zh_CN.md)：存储、算术、提取、gadget 乘法、CMUX 和可复用工作区 |
| 加密与求值 | [primus_lwe](crates/primus_lwe/README.zh_CN.md)、[primus_glwe](crates/primus_glwe/README.zh_CN.md)、[primus_ntru](crates/primus_ntru/README.zh_CN.md)：密钥与方案原语；[primus_glwe_rns](crates/primus_glwe_rns/README.zh_CN.md)：CRT/DCRT GLWE 和 hybrid-RNS 密钥切换 |
| BFV/BGV 系数与槽流程 | [primus_bfv](crates/primus_bfv/README.zh_CN.md)：BFV 参数、消息缩放与恢复；[primus_bgv](crates/primus_bgv/README.zh_CN.md)：p 倍误差与精确 centered 恢复；两者消费共享 batching |
| TFHE | [primus_tfhe](crates/primus_tfhe/README.zh_CN.md)：共享外部 LWE 客户端、LUT、PBS trait 和 Boolean 求值；上方两个家族 crate 与三个后端负责绑定参数、密钥和执行过程 |

BFV 已支持系数/槽线性与明文求值、RNS 密文乘法/square、原生 relin/换钥/密文旋转及精确舍入降模；BGV 已支持 q_i≡1 mod p 下的系数/槽私钥与公钥加密、乘法/square、p-preserving relin/换钥/密文旋转、前缀层级及精确 centered 恢复。CKKS 尚待实现。BFV 乘法可显式选择 Exact/HPSPOVERQ，并提供使用临时工作基的有限 ordinary BFV HPSPOVERQLEVELED 参数工厂，见[算术与密钥前提](guides/development/bfv-working-basis.md)。两方案的求值密钥可选 Radix/Native Hybrid，后者显式扩大 key modulus 到 QP，见[原生密钥契约](guides/development/native-hybrid-keys.md)。

应用库位于同级独立仓库：[primus_omr](../primus_omr/README.zh_CN.md) 提供 clue 检测、board 编码和消息恢复；[primus_high_prec_lut](../primus_high_prec_lut/README.zh_CN.md) 对多个独立加密的 chunk 执行高精度查表。它们不是本 workspace 的成员，示例、测试和基准请在各自仓库根目录运行。

## 构建与进一步阅读

默认 features 使用 stable Rust；可选 `simd` 需要 nightly。在仓库根目录运行 `cargo check --workspace --all-targets` 或 `cargo doc --workspace --no-deps`。仓库设置了 `target-cpu=native`，分发到其他 CPU 的二进制需要显式调整构建配置。

- [测试指南](guides/development/testing.md)：普通测试、doctest、feature 覆盖和独立的示例/基准 smoke。
- [TFHE 数值契约](guides/development/bootstrapping-contracts.md)：旋转舍入、首次提升、one-hot 与 MVB 的数学条件。
- [贡献规范](AGENTS.md)与 [justfile](justfile)：仓库开发约定和便捷命令。

## 许可证

可选择 [Apache License 2.0](LICENSE-APACHE-2.0) 或 [MIT License](LICENSE-MIT)。
