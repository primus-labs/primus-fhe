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

消息和解码输出使用系数类型 `T`，值为 `[0,t)` 内的规范剩余。无符号嵌入将消息提升到 `[0,t)`，中心嵌入提升到 `[-floor(t/2),ceil(t/2))`，包括 `t=2` 时的 `1 -> -1`。累加器与解码输入必须是 codec 密文模数下的规范剩余。这些密文输入范围由调用方保证，编码器不会验证。

Rounded 编码对整数提升舍入，中点远离零。两种单模数 codec 都对规范相位乘以 `t/q` 后舍入（中点向上），结果模 `t`。只有 `t` 整除 `q` 时，才能用 `delta=q/t` 将解码写成 `round(c/delta) mod t`；仅有舍入后的尺度是二次幂，不足以成立。

`RoundedCodec` 要求 `t >= 2` 且 `q > t`。`ScaledCodec` 还检查 `abs(t*delta-q)*(t-1) < q/2`，其中 `delta=round(q/t)`，中点向上。这是两种嵌入无噪声恢复的充分条件，并保证 `(t-1)*delta < q`。对于整数提升 `m` 和相位噪声 `e`，Scaled 的恢复充分条件为 `abs((t*delta-q)*m + t*e) < q/2`。

`RoundedCodec::try_new` 和 `ScaledCodec::try_new` 对非法数值域或不满足固定尺度恢复界返回 `CodecError`；`new` 在相同错误下 panic。这些检查不建立加密或求值的噪声预算。生产方与消费方必须使用一致的 codec、embedding 和模数。

只需要解码时，使用 `MessageDecoder::from(&codec)`。单模数切片方法使用 `_to` 表示独立输出，`_assign` 表示原地更新。批量编码在写入前检查消息范围和精确长度；添加编码消息的方法保留累加器原有内容。

## BFV RNS

启用 `rns` feature 后，`BfvRnsCodec::try_new(plaintext_modulus, base_q, gamma_modulus)` 在有序密文基的乘积 `Q` 下准备系数缩放。模数或恢复条件无效时返回 `BfvRnsCodecError<T>`；`new` 在相同错误下 panic。构造器检查[模数范围与互素条件](src/bfv_rns/mod.rs)，以及 `Q > 4*(Q % t)*(t-1)` 和 `gamma > 4*k`，其中 `k` 为密文模数数量。这些保守界保证无噪声恢复，不建立加密的噪声或安全预算。

对于相位 `delta*m+e`，其中 `delta=floor(Q/t)`，解码的充分条件为 `abs(t*e-(Q % t)*m)/Q + k/gamma < 1/2`。

给定完整相位噪声幅度上界 `E`，在准备参数时调用 `validate_noise_bound(E, embedding)`。它检查 `(t*E + (Q % t)*A)/Q + k/gamma < 1/2`，其中 unsigned 的 `A=t-1`，centered 的 `A=floor(t/2)`。失败返回 `InsufficientNoiseRecovery`；这是充分条件，可能拒绝实际仍能解码的情形。`E` 须包含加密与求值的全部噪声贡献。

`encode_coeffs_to` 按基的顺序输出系数域 `CrtPolynomial`；`add_encode_coeffs_assign` 加到已有的规范累加器上。多项式长度由明文切片决定。`decode_coeffs_to` 会覆盖系数域输入，并要求工作区恰好包含 `decode_scratch_len(output.len())` 个元素：单模数基为零，其他基为一个 RNS 多项式的大小。变换域数据须先做逆 NTT 再解码。

每个输入 residue 必须是其对应基模数下的规范剩余。自定义模数 context 还须满足 codec 继承的[跨模数基转换契约](../primus_rns/README.zh_CN.md#基转换)；提供的 Barrett context 已满足该条件。该编码器是 BFV 的组成部分，并非完整 BFV 方案。

## 整数槽与子环

启用 `batching` 后，对满足 `p = 1 mod 2n` 的素数明文模数，构造并复用 `BatchingEncoder::try_new(PolyLength::new(n), BarrettModulus::new(p))`。已有 `U64NttTable` 要求 `p < 2^62`，`PolyLength` 支持范围从 `n = 32` 开始。与底层 NTT 相同，素性是调用方前提；构造器检查变换是否可用。

布局有两行，每行 `n/2` 个槽，分别在最小本原 `2n` 次单位根的 `5^j` 和 `-5^j` 次幂上求值。普通调用可用 `encode(slots)` 返回 `n` 个系数，将槽前缀的缺省部分补零；`decode(coefficients)` 从恰好 `n` 个规范系数返回全部 `n` 个有序槽。编码分配一个结果向量；解码分配结果及一个临时 `n` 元素变换缓冲区。两种入口都要求输入值在 `[0,p)` 内，并复用下面的 prepared 操作。

`encode_to(slots, coefficients)` 接受不超过 `n` 个槽的前缀，将缺省槽清零，并输出恰好 `n` 个系数。`decode_to(coefficients, slots, scratch)` 要求三个切片长度均恰好为 `n`。这些 prepared 调用不分配内存，并在写入前检查明文规范范围与完整长度。

`rotation_exponent(k)` 返回使每行向左移动 `k` 个槽的多项式自同构指数；负数表示向右旋转。`row_swap_exponent()` 交换两行而不反转行内顺序。`automorphism_slots_to` 执行对应的**明文**置换。密文自同构及密钥切换属于方案层。

明文槽容量 `n` 可以小于密文环维数 `N`。`embed_to` 输出 `f(X^(N/n))`，非 `N/n` 倍数位置的系数全部清零；`extract_to` 在方案解密并解码系数后检查并反转该嵌入。只要求 `2n` 整除 `p-1`，无需 `p` 支持完整 `N` 维明文变换。这两个辅助函数都不改变密文或完整 `N` 维秘密。例如 `n=32, N=128, p=193` 支持 32 个子环槽，尽管模 193 不支持 128 槽变换。嵌入与提取都要求 `N >= n` 且 `N` 为二次幂。

通过 `cargo test -p primus_encoding --features batching --test batching --test batching_allocation` 运行独立直接求值、负循环卷积、自同构及分配检查。

## 相位误差诊断

`phase_error_magnitude(phase, expected_phase, modulus)` 用系数类型返回精确的非负圆周距离，范围为 `[0, floor(q/2)]`。它支持 Native 的 `2^BITS` 模数，无需浮点数转换。`phase_error_magnitude_slice_to` 将逐项距离写入调用方切片；三个切片长度必须一致，空切片也遵循此规则。长度不匹配在写入前 panic；规范 residue 由调用方保证。

先通过加密库提取系数域 phase，再用与该 phase 一致的 codec、embedding 和模数编码**预期消息**。例如：

```rust
use primus_encoding::{PlaintextEmbedding, RoundedCodec, phase_error_magnitude};
use primus_modulus::PowOf2Modulus;

let modulus = PowOf2Modulus::new(256u64);
let codec = RoundedCodec::new(4, modulus);
let expected_phase = codec.encode_value(0, PlaintextEmbedding::Unsigned);
let phase = 64; // 预期消息是 0，但这个 phase 会解码为 1。
assert_eq!(phase_error_magnitude(phase, expected_phase, modulus), 64);
```

如果重编码解码所得的值，这个例子的 residual 为零，会掩盖错误消息。解码是否正确仍须单独判断。圆周距离没有符号，不能恢复已绕模的整数误差，也包含 phase 中已有的变换或求值误差。逐 limb 的 RNS 距离不代表乘积模数下的整体误差。

## 进一步阅读

[公开 API 源码](src/lib.rs)记录方法契约。运行命令与测量对象见[单模数基准](benches/plaintext_codec.rs)和 [RNS 基准](benches/bfv_rns.rs)；验证入口见[测试指南](../../guides/development/testing.md)。

## Feature

- 默认：单模数编码器与相位误差诊断。
- `rns`：启用 BFV RNS 系数编码与解码。
- `batching`：独立于 `rns`，启用固定 `u64` 整数槽与明文子环嵌入。
- `simd`：启用 nightly SIMD 算术，不会单独启用 `rns` 或 `batching`。
