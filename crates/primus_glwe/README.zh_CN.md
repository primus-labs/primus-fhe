# primus_glwe

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

单模数 GLWE 密钥和运算，分别提供 NTT 与原生环面 Fourier 表示。下文 `k` 为 GLWE 维数，`N` 为多项式长度。

## 快速开始

下面使用 u64 和 NTT 展示普通消息与 encoded/phase 两条路径。调用方直接依赖 `primus_glwe`（启用 `ntt`）、`primus_ntt`、`primus_poly`、`primus_modulus`、`primus_encoding` 和 `rand`。N=32 仅用于简短的功能示例，不是安全参数。

```rust
use primus_encoding::PlaintextEmbedding;
use primus_glwe::{GlweDimension, GlweParameters, NttGlweSecretKey, SecretKeyDistr};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U64NttTable};
use primus_poly::Polynomial;
use primus_shape::PolyLength;

let poly_length = PolyLength::new(32);
let modulus = BarrettModulus::new(132_120_577u64);
let table = U64NttTable::new(poly_length, modulus).unwrap();
let params = GlweParameters::new(
    GlweDimension::new(1),
    poly_length,
    16,
    modulus,
    SecretKeyDistr::UniformBinary,
    0.7,
);
let mut rng = rand::rng();
let (_coeff_secret, secret) = NttGlweSecretKey::generate_pair(
    params.size(),
    params.encryption_parameters(),
    &table,
    &mut rng,
);
let message = Polynomial::new(vec![3u64; poly_length.get()]);
let embedding = PlaintextEmbedding::Unsigned;

// 普通消息：适配层使用参数中的 codec。
let mut ciphertext = secret.encrypt_message(&message, &params, embedding, &table, &mut rng);
assert_eq!(
    secret.decrypt_message(&ciphertext, &params, &table),
    message
);

// 已编码输入和提取出的 phase 都是系数多项式。
let codec = params.plaintext_codec();
let mut encoded = Polynomial::new(vec![0; poly_length.get()]);
codec.encode_slice_to(message.as_ref(), encoded.as_mut(), embedding);
secret.encrypt_encoded_to(
    &encoded,
    &mut ciphertext,
    params.encryption_parameters(),
    &table,
    &mut rng,
);
let mut phase = Polynomial::new(vec![0; poly_length.get()]);
secret.decrypt_phase_to(&ciphertext, &mut phase, modulus, &table);
let mut decoded = vec![0; poly_length.get()];
codec.decode_slice_to(phase.as_ref(), &mut decoded);
assert_eq!(decoded, message.as_ref());
```

用 `encrypt_message_to` 复用密文存储，无需单独的 encoded 多项式。重复请求保留参数、表、密钥和输出；Fourier 运算还需复用 FFT engine 与工作区。

## 参数与密钥

| 参数 | 用途 |
| --- | --- |
| `GlweParameters` | 带 `ScaledCodec` 的普通加解密 |
| `GlweEncryptionParameters` | 密钥生成、encoded/零加密所需的模数和采样器；无 codec 或布局 |
| `GlevParameters` / 其别名 `GgswParameters` | GLWE 布局、加密参数及 gadget 分解；无明文 codec |

普通消息使用 `GlweParameters::try_new`；仅需 gadget 时使用 `GgswParameters::try_new(size, modulus, secret_distr, decomposition, sigma)`。其中 `size` 为 `GlweSize`，`decomposition` 为 `DecompositionConfig`，`sigma` 以系数为单位。已有普通参数时，可用 `GlevParameters::try_with_glwe_params(&glwe_params, decomposition)` 派生同一环上的 gadget 参数，并复用已准备的采样器。

[PolyLength](../primus_shape/README.zh_CN.md#多项式长度) 构造一次，供参数、表和工作区复用。GLWE 维数使用 `GlweDimension`；固定秘密重量作用于全部 `k*N` 个系数，不是逐多项式分别应用。可失败构造器报告布局、编码或采样配置错误，不证明变换可用性及噪声/安全预算。

| 密钥 | 表示与用途 |
| --- | --- |
| `GlweSecretKey<T>` | 有符号系数；采样及求值密钥生成 |
| `NttGlweSecretKey<T>` | 模 `q` 的规范 NTT 剩余类；NTT 加解密 |
| `FourierGlweSecretKey` | 按整数尺度变换的 Fourier 解密私钥 |
| `FourierGlweEncryptor` | 借用系数私钥，准备精确 native 加密和建钥 |
| `NttGlwePublicKey<S>` | NTT 零加密；公钥加密 |

NTT 的 `generate_pair` 同时返回系数私钥和变换私钥。Fourier 先用参数的 sampler 生成 `GlweSecretKey`，再调用 `FourierGlweEncryptor::try_new(&secret, params.encryption_parameters())`。需要解密时才另用 `FourierGlweSecretKey::from_coeff_secret_key(&secret, fft)`。Encryptor 借用系数私钥，使用期间须保持私钥存活。

后续操作须保持构造时的表示：相同模数和长度不能证明 NTT 根、求值顺序或秘密身份相同。`NttGlweSecretKey::new` 检查导入布局，规范剩余类、分布和变换来源由调用方保证。公钥原始字节使用本机字节序，不包含参数元数据。私钥缓冲区析构时擦除；显式清零后应丢弃私钥。

## 加密与解密

对秘密多项式 `s_i`，GLWE 相位为 `b - sum_i a_i*s_i = Encode(m) + e`。

| 方法 | 输入或结果 |
| --- | --- |
| `encrypt_message` / `encrypt_message_to` | `[0, t)` 中的消息和显式 `PlaintextEmbedding`；分配 / 覆盖密文 |
| `encrypt_encoded_to` | 已编码系数多项式；不进行明文缩放 |
| `encrypt_zeros` / `encrypt_zeros_to` | 零多项式；分配 / 覆盖密文 |
| `decrypt_phase_to` | 系数域相位，不解码 |
| `decrypt_message` / `decrypt_message_to` | 解码后的系数多项式；分配 / 覆盖输出 |

消息方法使用 `GlweParameters`；encoded/零加密和公钥生成使用 `GlweEncryptionParameters`。`Unsigned` 与 `Centered` 均接收 `[0, t)` 中的规范剩余类，centered 的 `t-1` 表示 `-1`；两者使用相同解码器。解码结果保留系数类型 `T`。

NTT 私钥运算不需要工作区。Fourier 加密复用准备好的 encryptor，无需额外传工作区；解密使用 `FourierGlweDecryptWorkspace`。NTT 公钥加密使用 `NttGlwePublicEncryptWorkspace<T>`。复用这些资源，调用方持有的明文和相位输出按自身生命周期擦除。Encryptor 只在准备时检查声明的 sampler 支持，拥有析构时擦除的精确乘积缓存和一行系数缓冲。导入任意系数可用 `FourierGlweEncryptor::from_coeff_secret_key`，采用完整 signed 字宽界；u64 此时使用成本较高的 O(kN²) schoolbook 乘法。

NTT 还提供 `encrypt_message_coeff_to`、`decrypt_phase_coeff_to` 和 `decrypt_message_coeff_to`，用于系数密文。最后一个参数是无需预先清零的 N 元素 scratch 切片。加密后其中保留秘密相关乘积，宜使用 `zeroize::Zeroizing<Vec<T>>` 等可擦除的拥有者。

已编码 NTT 输入必须是 `[0, q)` 中的规范系数。密钥、参数、表和输出布局须匹配；Fourier 值须使用密钥生成时的同一 FFT 表实例。非法明文可能在部分写入或消耗随机数后失败。精确缓冲区及失败契约见[私钥](src/secret_key)和[公钥](src/public_key)方法。

做[相位误差诊断](../primus_encoding/README.zh_CN.md#相位误差诊断)时，用实际 codec 和 embedding 编码**预期消息**，再与相位比较。先解码再重新编码不能提供独立参考。

## Gadget 密文

`encrypt_glev_to` 和 `encrypt_ggsw_to` 对系数域环多项式应用 gadget 缩放，不做普通明文编码。GGSW 控制位是常数多项式 `0` 或 `1`。NTT 从 `GadgetSize` 构造 gadget 工作区：GLev 需要匹配多项式长度，GGSW 还需匹配层数。Fourier 在不同 gadget 基与层数间复用同一 encryptor，行对角项在 native 环中完成后才 FFT。

`encrypt_ggsw_constant_batch_to` 写入连续的变换域 GGSW：NTT 为 `input.len() * params.ggsw_len()` 个剩余类，Fourier 为 `input.len() * params.fourier_ggsw_len()` 个复数。NTT 常数须是模 q 的规范剩余类，Fourier 常数使用原生环值。两后端也提供 `encrypt_ggsw_constant_batch_coeff_to` 写入系数输出；Fourier 直接写出精确 native 行，不需要 FFT scratch 或 inverse 舍入。`encrypt_message_coeff_to` 同样可直接写出普通系数密文。

## 求值原语

| 求值密钥 | 运算 |
| --- | --- |
| `NttGlweKeySwitchingKey` / `FourierGlweKeySwitchingKey` | 更换 GLWE 秘密，可改变维数，保持环长度及模数 |
| `NttGlweAutomorphismKey` / `FourierGlweAutomorphismKey` | 对 `[1, 2N)` 中奇数 `d` 应用 `X -> X^d`，返回到原秘密下 |
| `NttGlweSchemeSwitchKey` / `FourierGlweSchemeSwitchKey` | 同一秘密下，将系数 GLev 转为变换域 GGSW |

用 `GlweKeySwitchingParameters::new(input_dimension, output_glev)` 准备完整参数，再传给两个 key-switching key 的 `generate` 方法。输入秘密须匹配声明的维数和多项式长度；`output_glev` 提供目标布局、分解基及密钥行加密噪声。Fourier 生成时传入目标准备态，不再分别传变换私钥和 gadget 工作区。

求值密钥持有布局及分解基，匹配的工作区构造一次即可复用。自同构提供系数域 `apply_to` 和变换域 `apply_ntt_to` / `apply_fourier_to`；直接 Fourier 输出的舍入可能不同于系数往返路径。

[Scheme switching](src/scheme_switch) 在 NTT 生成时使用相互匹配的系数及变换私钥，Fourier 生成时只传一个目标准备态。Fourier 自同构和 trace 生成同样只接收准备态，内部从目标秘密派生所需明文。输出 gadget 缩放继承输入 GLev；`key_basis()` 控制分解，可以不同于输出基。传入的外积工作区须匹配 `key.key_size()`。

## Trace、投影与展开

`NttGlweTraceKey` 和 `FourierGlweTraceKey` 操作系数密文。下表中 `M` 是输入消息，目标消息省略求值噪声。

| 方法 | 目标消息 |
| --- | --- |
| `apply_to` / `apply_reverse_to` | 常数 `N*M[0]` / `M[0]` |
| `apply_partial_to(input, r, ...)` | `d * sum_j M[j*d] X^(j*d)`，其中 `d=N/r` |
| `apply_reverse_partial_to(input, r, ...)` | `sum_j M[j*d] X^(j*d)` |
| `project_coefficient_to` / `project_coefficients_to` | 常数 `M[index]` / 按选择顺序排列的常数 |
| `project_prefix_coefficients_to(input, count, ...)` | 前 `count` 个系数各自作为常数；无需零尾部 |
| `expand_coefficients_to` | 全部 N 个系数各自作为常数 |
| `expand_partial_coefficients_to(input, count, ...)` | 前 `count` 个常数，要求消息尾部为零 |

启用 `split-trace` 后，`SplitFourierGlweTraceKey::generate` 为 native u64、rank-1 且系数在 `{-1,0,1}` 的秘密提供高精度前缀投影；用 `key.new_workspace()` 分配匹配空间。精确系数密钥生成使用辅助 NTT/CRT，在线只保留 low35/high29 Fourier 谱。Trace payload 和逆变换次数翻倍，这是显式的精度/成本取舍，不是噪声余量保证。完整契约见 [split trace](src/trace/split.rs)。

部分 trace 接收 `1..=N` 内的二次幂 `r`，在一个 GLWE 中保留等间距位置。`r=N` 复制输入，`r=1` 为完整 trace。Reverse trace 在每次自同构及相加前归一化：NTT 乘 `2^-1 mod q`，Fourier 对无符号系数做 `floor(x/2)`。NTT 域运算不能直接继承环面 RevHomTrace 的噪声界。

投影接受任意索引，包括重复索引和空选择；前缀投影接受 `0..=N` 中任意数量。每个选中系数都需要一次完整 reverse trace，数量为一也如此。部分展开则接收 `1..=N` 中的二次幂数量：一时复制输入，N 时为完整展开。它只归一化一次，误差行为与投影不同。

部分展开要产生常数，**消息**的 `count..N` 系数必须为零；否则输出 i 的目标是 `sum_j M[i+j*count] X^(j*count)`。密文和噪声尾部无需为零，所有输出仍保持环长度 N。完整归一化及工作区契约见 [trace 方法](src/trace)。

## LWE packing

根据输入秘密及所需系数位置选择 packing。两种路径均要求输入输出模数和消息编码相同；目标消息为零的位置仍可含噪声。

| 路径 | 输入秘密及数量 | 目标消息 |
| --- | --- | --- |
| Trace key 的 `pack_lwe_to` / `pack_lwes_to` | 维数 `k*N` 的展平 GLWE 秘密；数量 p 为 `1..=N` 内二次幂 | `sum_i m[i] X^(i*N/p)`；仅 p=N 时槽位相邻 |
| `NttLwePackingKeySwitchingKey` / `FourierLwePackingKeySwitchingKey` | 独立 LWE 秘密；数量 p 可为 `1..=N` 内任意值 | `key_switch_to`：单个常数；`pack_lwes_to`：`sum_i m[i] X^i` |

Trace packing 使用 [RevHomTrace](https://github.com/Stirling75/RevHomTrace/blob/main/src/glwe_conv_rev.rs)。批量用 `NttGlwePackingWorkspace::new(size, p)` 或 Fourier 对应类型，p 在工作区构造时固定；单 LWE 使用 trace 工作区。

独立密钥 packing 允许输入维数不同于 `k*N`。从输入 `LweSecretKeyRef`、输出 GLWE 私钥和 GLev 参数生成密钥，再复用匹配输出布局的 GLWE key-switching 工作区，批量数量可以变化。噪声预算须覆盖输入噪声、秘密加权的分解误差及密钥噪声，Fourier 还包含浮点误差。完整布局及缓冲区契约见 [packing key switching](src/packing_key_switch)。

## Features

默认 features 为空。`ntt` 启用 NTT 运算；`fourier` 启用普通 Fourier API 及系数建钥使用的内部辅助 NTT/CRT 依赖，不选择 FFT engine，也不启用 NTT GLWE API。使用 `rustfft` 或 `tfhe-fft` 同时启用 Fourier 及具体 engine，两者可共存。另加 `split-trace` 启用 Split35 密钥，例如 `--features rustfft,split-trace`。`simd` 只转发给已启用的算术依赖，不启用变换后端。

测试、示例和基准声明 `required-features`；缺少时 Cargo 会跳过整个 target。按相应运行命令选择 features。

## 更多资料

逐方法契约见 [API 源码](src)，负载与运行命令见[基准指南](benches/README.zh_CN.md)，验证命令见 workspace [测试指南](../../guides/development/testing.md)。
