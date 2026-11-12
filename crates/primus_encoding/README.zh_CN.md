# primus_encoding

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

Primus FHE 的明文系数编码、解码与整数槽打包。

## API

| 编码器 | 编码规则 | 当前用途 |
| --- | --- | --- |
| `RoundedCodec<T,M>` | `round(lift(m)*q/t) mod q` | LWE 和 TFHE 查找表 |
| `ScaledCodec<T,M>` | `lift(m)*round(q/t) mod q` | 单模数 GLWE/NTRU |
| `BfvRnsCodec<T,M>` | `lift(m)*floor(Q/t) mod Q` | RNS 系数缩放（`rns` feature） |
| `BatchingEncoder` | `w^(±5^j)` 上的两行求值 | BFV/BGV 共享整数槽（`batching` feature，`u64`） |

单模数构造器为 `new(plaintext_modulus, ciphertext_modulus)`，例如 `RoundedCodec::new(256u64, NativeModulus::new())` 或 `RoundedCodec::new(7u64, BarrettModulus::new(131))`。构造一次后复用 codec。`t` 整除 `q` 时两种编码都使用精确尺度 `q/t`；否则 Rounded 对每个消息舍入，Scaled 使用统一的整数尺度。

TFHE 普通 LUT 的输出 `RoundedCodec` 使用 accumulator 模数，明文模数可与输入不同。解码使用返回密文模数下、相同输出明文模数的 codec；NTRU 的 Q→q 路径尤其需要区分二者。见[输出编码指南](../primus_tfhe/README.zh_CN.md#选择输出编码)。

前三种类型负责系数编码。`BatchingEncoder` 在方案执行各自的消息提升前，转换明文槽与系数。目前未实现 CKKS 的典范嵌入。

## 编码契约

消息和解码输出均为 `[0,t)` 内类型为 `T` 的规范剩余。无符号嵌入提升到 `[0,t)`，中心嵌入提升到 `[-floor(t/2),ceil(t/2))`。调用方须保证累加器和解码输入是 codec 密文模数下的规范剩余。

Rounded 编码对整数提升舍入，中点远离零。两种单模数 codec 都将规范相位乘以 `t/q` 后舍入，中点向上，再模 `t`。只需要解码时使用 `MessageDecoder::from(&codec)`。见[解码契约](src/decode.rs)。

两种 codec 均要求 `t >= 2` 且 `q > t`。Scaled 还检查固定尺度下的无噪声恢复条件。用 `try_new` 处理不合要求的配置，另行建立覆盖加密和求值的噪声预算。生产方与消费方须使用一致的 codec、embedding 和模数。见 [Rounded](src/rounded.rs) 和 [Scaled](src/scaled.rs) 恢复契约。

## BFV RNS

启用 `rns` 后，用 `BfvRnsCodec::try_new(t_modulus, base_q, gamma_modulus)` 在有序密文基的乘积 `Q` 下准备系数缩放。构造器检查模数和无噪声恢复条件。准备参数时，给定覆盖完整相位误差的上界 `E`，调用 `validate_noise_bound(E, embedding)`。见[构造器](src/bfv_rns/mod.rs)及[恢复条件](src/bfv_rns/decode.rs)。

`encode_coeffs_to` 按基的顺序写出系数域 `CrtPolynomial`。解码前对 NTT 数据做逆变换，并提供规范剩余类。`decode_coeffs_to` 会覆盖输入，工作区长度为 `decode_scratch_len(output.len())`。自定义模数 context 须满足[跨模数基转换契约](../primus_rns/README.zh_CN.md#基转换)。

## 整数槽与子环

启用 `batching` 后，调用 `BatchingEncoder::try_new(PolyLength::new(n), BarrettModulus::new(p))`。调用方提供满足 `p = 1 mod 2n` 且 `p < 2^62` 的素数 `p`。输入为 `[0,p)` 内的规范剩余。`encode` 接受槽前缀并将其余槽补零，`decode` 返回全部 `n` 个有序槽。使用 `encode_to` 和 `decode_to` 复用缓冲区。见[槽布局与明文自同构](src/batching.rs)。

对于二次幂密文环长度 `N >= n`，`embed_to` 写入 `f(X^(N/n))`。`extract_to` 在解密并解码系数后检查并反转该嵌入。明文变换长度仍为 `n`，密文和秘密保持长度 `N`。见 [BFV 子环示例](../primus_bfv/examples/subring_slots.rs)。

## 相位误差诊断

用 `phase_error_magnitude` 或 `phase_error_magnitude_slice_to` 比较规范系数相位。按提取相位所用的 codec、embedding 和模数编码**预期消息**。将解码结果重新编码可能掩盖错误。结果是无符号圆周距离。RNS 的逐分量距离衡量各分量模数下的误差。见[可运行示例与完整契约](src/phase_error.rs)。

## 进一步阅读

[公开 API 源码](src/lib.rs)记录方法契约。运行命令与测量对象见[单模数基准](benches/plaintext_codec.rs)和 [RNS 基准](benches/bfv_rns.rs)；验证入口见[测试指南](../../guides/development/testing.md)。

## Feature

- 默认：单模数编码器与相位误差诊断。
- `rns`：启用 BFV RNS 系数编码与解码。
- `batching`：独立于 `rns`，启用固定 `u64` 整数槽与明文子环嵌入。
- `simd`：启用 nightly SIMD 算术，不会单独启用 `rns` 或 `batching`。
