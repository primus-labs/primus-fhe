# primus_lattice

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

`primus_lattice` 为 [Primus FHE](../../README.zh_CN.md) 提供密文存储、表示转换和底层格运算，由 GLWE/NTRU × Fourier/NTT 四条 TFHE 路径以及 RNS GLWE 实现共同使用。

密钥生成、加密参数、编码策略、噪声管理和完整同态计算由 [`primus_glwe`](../primus_glwe)、[`primus_ntru`](../primus_ntru)、[`primus_glwe_rns`](../primus_glwe_rns) 等更高层负责。

## 密文类型

以下用 `N` 表示多项式长度，`k` 表示 GLWE 掩码维数，`L` 表示 gadget 分解层数，`m` 表示 RNS 模数数量。多项式运算使用模 `X^N + 1` 的负循环环。

| 类型族 | 系数形式的布局 | 支持的表示 |
| --- | --- | --- |
| `Lwe` | 标量掩码，后接一个 body 标量 | 系数 |
| `MultiMsgLwe` | 按常数项抽取顺序排列的长度为 `N` 的掩码，后接保留的 body 系数 | 打包的 RLWE 样本 |
| `Glwe` | `k` 个掩码多项式，后接一个 body 多项式 | 系数、NTT、Fourier、CRT/DCRT |
| `Glev` | 按分解顺序排列的 `L` 个 GLWE 密文 | 系数、NTT、Fourier、CRT/DCRT |
| `Ggsw` | `k+1` 行 GLev | 系数、NTT、Fourier、CRT/DCRT |
| `Ntru` | 单个多项式 `h`，在秘密多项式 `f` 下的相位为 `f*h` | 系数、NTT、Fourier |
| `Nlev` / `Ngsw` | 按分解顺序排列的 `L` 个 NTRU 多项式 | 系数、NTT、Fourier |

RLWE、RLev 和 RGSW 分别使用 `Glwe`、`Glev` 和 `Ggsw`，并配合 `GlweSize::new(GlweDimension::new(1), PolyLength::new(N))`；NTT 和 CRT/DCRT 表示同样使用维度为 1 的布局。

类型通过对应模块导出，例如 `glwe::Glwe`、`ggsw::NttGgsw`、`ngsw::FourierNgsw`。前缀表示数据形式。`Torus*` 是系数类型在 native torus 场景下的别名，不会强制模数，也不执行编码。

NLev 与 NGSW 的存储形状相同，但语义不同：`beta` 的 NLev 各层相位为 `v_i*beta`，而 `beta` 的 NGSW 各层相位为 `v_i*f*beta`。它们适用的 gadget product 不同，因此保留为独立类型。

## 存储与布局

密文包装类型以存储 `S` 为泛型，通过 [`primus_data`](../primus_data/README.zh_CN.md) 支持拥有或借用的数据。`as_view()` / `as_mut_view()` 借用完整存储，不复制元素或改变表示；`into_inner()` 返回原存储。使用多项式和密文的语义迭代器遍历分量、层和行，无需重新打包。

`LweIter` / `LweIterMut` 的分块长度包含 body，`Lwe::lwe_len()` 返回该长度。迭代器忽略不完整尾部，调用方须先保证完整长度。`MultiMsgLweIter` 遍历 packed 容器，不是从一个共享 mask 中抽取单条样本。

- 普通 GLWE 占 `(k+1)*N` 个元素，GLev 占 `L*(k+1)*N`，GGSW 占 `(k+1)*L*(k+1)*N`。
- CRT 的每个多项式包含 `m` 个长度为 `N` 的系数块；DCRT 保持相同布局，但块内为 NTT 数据。嵌套 gadget 顺序为 `[row][level][component][modulus][coefficient/evaluation]`。
- Fourier 多项式包含 `N/2` 个复数元素，顺序由后端定义。密文使用归一化 torus 变换；多项式乘数的尺度须符合相应运算契约。
- RNS GLev 乘法还接受 `primus_poly::BigUintPolynomial` 输入，按系数排列，每个系数使用固定宽度的小端 limb 序列。

`LweDimension` 和 `GlweDimension` 表示正的 mask 计数，分别用 `.ciphertext_len()` 和 `.component_count()` 返回包含 body 的 `n+1` 和 `k+1`。这些类型保证计数可表示，不代表安全参数；原始密文和秘密切片仍允许零维。

用 `GlweSize`、`GadgetSize`、`RnsGlweSize` 和 `RnsGadgetSize` 的长度访问器分配存储。这些类型检查组合长度溢出和 RNS 模数数量；`LweDimension::from(glwe_size)` 派生提取维数 `kN`。它们不验证实际缓冲区、变换表、模数或安全性。

布局和工作区接收 [`primus_shape::PolyLength`](../primus_shape/README.zh_CN.md#多项式长度)。`.get()`、`.log_n()` 和 `.fourier_poly_len()` 分别返回 `N`、`log2(N)` 和 `N/2`。

## 序列化

`serde` 为存储支持相应 trait 的 `Lwe<S>` 和 `MultiMsgLwe<S>` 提供序列化。

序列化仅保存原始系数。维数、packed mask/body 分界、模数、编码和密钥身份仍由外部提供；反序列化不验证这些条件。这不是带版本的密钥或参数格式。

## 运算与所有权

| 运算族 | 主要接口 |
| --- | --- |
| 基础算术 | `add_assign`、`sub_assign`、`neg_assign` 及相应输出形式 |
| Scalar/factor 算术 | `mul_scalar_*`、`mul_factor_*` 及支持的融合累加 |
| 多项式运算 | 系数/NTT 形式的单项式操作；NTT、Fourier、DCRT 形式的多项式乘法与累加 |
| 明文与 gadget 更新 | `add_plaintext_assign`、`set_trivial`、`add_gadget_diagonal_assign` |
| 表示转换 | `into_ntt_form`、`write_ntt_form`、逆变换到系数形式、`write_fourier_form`、`write_torus_form` |
| 样本抽取 | `extract_lwe_at_to`、GLWE 紧凑抽取、打包 RLWE 抽取、`inverse_extract_glwe_to` |
| 外积 | Fourier/NTT GGSW 与 NTRU gadget product；DCRT GLev 多项式乘法和 GGSW 乘法 |
| CMUX | GGSW/NGSW 的 `cmux_to`、`cmux_k_to`、`cmux_monomial_to` |
| Ternary 旋转 | NTT/Fourier GGSW 和 NGSW 的 `cmux_ternary_monomial_to` |

实际支持的接口取决于类型和表示。RNS scalar/factor 参数使用按模数顺序排列的 `primus_rns::Residues` 和 `ResidueFactors`。

`*_assign` 原地修改接收者，`*_to` 写入独立输出，`add_*_assign` 累加到已初始化的存储。消费式方法可能复用存储，返回新抽取样本的方法会分配；以具体方法契约为准。

外积可以输出系数，也可以通过 `external_product_ntt_to` / `external_product_fourier_to` 保留变换域结果。

`DcrtGgsw::external_product_to` 接收系数域的 `CrtGlwe` 输入并覆盖写入 `DcrtGlwe` 输出，使用匹配的 RNS 基、分解基、变换表和 `DcrtGlevMulWorkspace`。

NLev 的 `external_product_sum_to` 和 GGSW/NGSW 的 `cmux_k_to` 接收数量匹配的精确长度迭代器。可传入借用的 gadget 和多项式/密文视图；输出用 `output.as_mut_view()`，CMux 默认分支用 `default.as_view()`。候选项可来自 `GlweIter` / `NtruIter` 或借用的密文集合，无需收集视图。空求和写零，空 CMux 复制默认分支。Fourier 对聚合结果统一舍入，可能与逐项转回系数后相加不同。

完整 GLWE 抽取将全部 mask 多项式展平为 LWE mask；紧凑抽取要求省略的秘密后缀为零。`MultiMsgLwe` 保存按常数项抽取顺序排列的共享 mask，其抽取接口通过负循环旋转 mask 得到各个保留 body 系数的样本。逆抽取嵌入常数项 LWE 样本并将未使用位置清零，不恢复原 GLWE 明文的全部系数。

## 正确性与工作区契约

原始构造器和可变访问不保证密文有效。调用方须保证密钥、编码、尺寸、完整缓冲区长度、模数顺序、分解基及变换约定相容。Fourier 数据须使用运算所需的同一个 FFT 表实例及尺度。除方法另有说明外，模运算输入须是规范剩余；native 模数下所有整数位模式均为规范值。

这些底层运算有意省略部分检查，错误输入可能只处理共同前缀或完整分块而不报错。精确条件见 [API 源码](src/lib.rs) 中各方法的 `Correctness` 和 `Panics` 文档。

| 工作区 | 尺寸依据 |
| --- | --- |
| `NttGlweExternalProductWorkspace` / `FourierGlweExternalProductWorkspace` | `GadgetSize` 中的 GLWE 布局与分解层数 |
| `NttGlweTernaryCmuxWorkspace` / `FourierGlweTernaryCmuxWorkspace` | 固定 `GadgetSize` |
| `NttNtruExternalProductWorkspace` / `FourierNtruExternalProductWorkspace` | 多项式长度 |
| `NttNtruCmuxWorkspace` / `FourierNtruCmuxWorkspace` | 多项式长度与分解层数 |
| `DcrtGlevMulWorkspace` | RNS gadget 布局与乘积模数的 limb 宽度 |

工作区提供可复用 scratch，不验证密钥、basis、table 或模数身份。覆盖式外积会初始化所需缓冲区，合法调用之间无需 reset；累加接口要求输出已有有效值。GLWE 外积工作区的 `with_rebound` 临时改变分解层数，保持 GLWE 形状，并在调用结束后恢复原布局；`resize` 可改变缓冲区尺寸。

批量外积和 k-CMux 检查迭代器数量；缓冲区长度检查因操作而异，部分只使用 debug 断言。后续项无效或迭代器 panic 可能留下部分输出或 scratch；丢弃结果后，合法调用仍可复用工作区。具体检查与写入边界见相应方法文档。

CMux 的选择语义要求控制加密比特；k-CMux 要求至多一个控制比特为一。三元 `cmux_ternary_monomial_to` 使用互斥比特 `s⁺, s⁻`，理想旋转为 `X^(exponent * (s⁺-s⁻))`；指数须在 `0..2N`，零指数精确复制输入。控制须使用相同密钥、basis 和变换约定；Fourier 控制使用 native-torus 尺度和匹配的 native basis。噪声增长和可解密性由更高层负责。

## 示例

借用存储，把已经编码的多项式加到 body，再在显式模数下抽取第二个系数：

```rust
use primus_lattice::{GlweDimension, GlweSize, glwe::Glwe, lwe::Lwe};
use primus_shape::PolyLength;
use primus_modulus::BarrettModulus;
use primus_poly::Polynomial;

let size = GlweSize::new(GlweDimension::new(2), PolyLength::new(32));
let modulus = BarrettModulus::new(97u32);
let mut storage: Vec<u32> = (1..=size.glwe_len()).map(|i| i as u32).collect();
assert_eq!(storage.len(), size.glwe_len());
let mut ciphertext = Glwe::new(storage.as_mut_slice());
let plaintext = Polynomial::new(vec![10; size.poly_length().get()]);
ciphertext.add_plaintext_assign(&plaintext, modulus);

let mut sample: Lwe<Vec<u32>> = Lwe::zero(size.mask_len());
ciphertext.extract_lwe_at_to(1, &mut sample, size.poly_length().get(), modulus);
assert_eq!(&sample.a()[..2], &[2, 1]);
assert_eq!(sample.b(), 76);
```

此示例展示布局和算术，不执行随机加密，也不提供安全参数选择。

## Features

默认 features 为空，仅保留系数存储、布局和基础运算，不引入 NTT/FFT。

- `serde` 启用原始 `Lwe` 和 `MultiMsgLwe` 存储的序列化。
- `ntt` 启用 NTT 密文、转换、运算和工作区。
- `fourier` 启用对应的 Fourier 泛型接口，不选择具体 FFT 引擎。
- `rustfft` / `tfhe-fft` 同时启用 `fourier` 和对应 FFT 实现，可叠加使用。
- `rns` 启用 CRT/DCRT 密文及乘法工作区；DCRT 需要的 `ntt` 一并启用。
- `simd` 仅向已启用的算术依赖传播 nightly SIMD，不激活后端、FFT 引擎或 `rns`。
- `RnsGlweSize` 和 `RnsGadgetSize` 不依赖 `rns` feature。

各 target 显式声明所需表示和具体 FFT 实现。混合后端的对照测试需要全部对应 feature；缺失时 Cargo 跳过整个 target。

## 测试与基准

验证命令见 workspace [测试指南](../../guides/development/testing.md)。[基准指南](benches/README.md) 列出可独立运行的 target 和测量端点；完整 PBS 与连续读取计算密钥的成本须在上层测量。
