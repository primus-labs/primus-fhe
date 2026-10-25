# primus_distr

[English](README.md) | 简体中文

`primus_distr` 为 [Primus FHE](../../README.zh_CN.md) 提供离散概率分布与批量采样 helper，覆盖 binary/ternary secret、中心离散 Gaussian 噪声、模表示与有符号表示、 CRT 批量布局以及统计诊断。

> [!WARNING]
> 本 crate 属于实验性的 Primus FHE workspace。其 API、采样算法和数值契约尚不稳定， 可能随时发生不兼容修改。

## 主要分布

| 类型 | 输出与职责 |
| --- | --- |
| `BinaryDistr` | 从 `{0, 1}` 中均匀采样 |
| `SparseTernaryDistr<T>` | 以 `1/2`、`1/4`、`1/4` 的概率从 `{0, 1, -1}` 采样；`-1` 的表示由调用方提供 |
| `DiscreteGaussian<T>` | 将中心 Gaussian 样本编码为调用方所给模数下的规范无符号 residue |
| `SignedDiscreteGaussian<T>` | 使用有符号整数类型直接表示中心 Gaussian 样本 |
| `CDTSampler<T>` / `SignedCDTSampler<T>` | 显式选择的 portable 64-bit cumulative-distribution-table backend |
| `DiscreteZiggurat<T>` / `SignedDiscreteZiggurat<T>` | 用于较大 support 的显式离散 Ziggurat backend |

上表中的标量 sampler 类型均实现 `rand::distr::Distribution`。批量 helper 要求 RNG 同时实现 `rand::Rng` 与 `rand::CryptoRng`。

## 私钥分布参数

`SecretKeyDistr` 描述完整 binary、ternary、固定重量或 Gaussian 密钥的分布，不是标量 sampler。自定义概率使用 `binary(one_probability)` 或 `ternary(negative_one_probability, one_probability)`；各概率必须有限且位于 `[0, 1]`，ternary 概率之和不能超过一。各密码方案自行选择支持的变体。

| 构造函数 | 分布 |
| --- | --- |
| `fixed_hamming_weight_binary(length, weight)` | 均匀选取位置，恰好包含 `weight` 个 `1` |
| `fixed_hamming_weight_ternary(length, weight)` | 恰好包含 `weight` 个非零位置，各符号独立均匀随机 |
| `fixed_composition_ternary(length, negative_weight, positive_weight)` | 分别固定负一和正一的数量 |

重量作用于完整逻辑密钥。构造函数拒绝过大的重量及重量和溢出，但不保留长度；采样时按实际输出长度检查，在写入或取样前拒绝非法重量。

通过 `try_new(distribution)`（返回错误）或 `new(distribution)`（失败时 panic）准备 `SecretKeySampler<T>`。`sample_signed` / `sample_signed_to` 生成 `T::SignedInteger` 输出；`sample_encoded` / `sample_encoded_to` 生成规范 residue。`_to` 方法无分配地覆盖调用方存储。

`maximum_magnitude()` 返回样本幅度上界（包含端点）；Gaussian 支持集须适配对应的 signed 类型，binary 和 ternary 返回一。Encoded 采样前须保证 `modulus_minus_one >= maximum_magnitude()`，其中 `T::MAX` 表示 native 模数；`validate_modulus` 无需采样即可检查此条件。Sampler 不保存模数。完整契约与错误见[采样器 API](src/secret_key_sampler.rs)。

自定义 ternary 概率向下量化为 `2^-64` 的整数倍，总非零概率限制在一以内以处理浮点边界舍入。RNG 消费量及固定 seed 的输出可能随版本改变；完整密钥的空输出不保证不消耗随机数。

## 示例

```rust
use primus_distr::{SignedDiscreteGaussian, sample_crt_gaussian_values};
use rand::{SeedableRng, rngs::StdRng};

let gaussian = SignedDiscreteGaussian::<i64>::new(3.2).unwrap();
let moduli = [97_u64, 193];
let poly_length = 8;
let mut rng = StdRng::seed_from_u64(7);

let samples = sample_crt_gaussian_values(
    poly_length,
    &moduli,
    &gaussian,
    &mut rng,
);

assert_eq!(samples.len(), poly_length * moduli.len());
assert!(samples[..poly_length].iter().all(|&x| x < moduli[0]));
assert!(samples[poly_length..].iter().all(|&x| x < moduli[1]));
```

## Gaussian 构造与表示

`DiscreteGaussian` 与 `SignedDiscreteGaussian` facade 使用 12 个标准差的默认 tail cut。 构造过程会拒绝非有限参数、小于 `MIN_STANDARD_DEVIATION` 的标准差、所选输出类型无法 表示的 support，以及无法放入所给模数的 modular support。

截断 support 能放入 magnitude 上限为 255 的 portable CDT 表时，facade 选择 CDT backend；否则选择 Ziggurat backend。需要直接指定 tail cut 或 backend 时，应显式构造 `*CDTSampler` 或 `*Ziggurat`。

`DiscreteGaussian::new(sigma, modulus_minus_one)` 返回 `[0, modulus_minus_one]` 中的值。逻辑负样本 `-x` 编码为 `modulus_minus_one - x + 1`。`SignedDiscreteGaussian::new(sigma)` 则直接返回正值、 零和负值。

## 批量采样

`DiscreteGaussian` 和 `SignedDiscreteGaussian` 提供分配新存储的 `sample_vec(length, rng)` 和无分配的 `sample_to(output, rng)`。输出与 RNG 消费量等同于反复调用标量 `Distribution::sample`；空 Gaussian 批次不消耗随机数。Binary、ternary、固定重量、uniform 和 Gaussian 向量 helper 同样提供分配版本和 `_to` 版本。

CRT 批次使用 **modulus-major** 布局：对于 `N` 个系数与 `k` 个模数，输出包含 `k * N` 个元素：

```text
[a_0 mod q_0, ..., a_(N-1) mod q_0,
 a_0 mod q_1, ..., a_(N-1) mod q_1,
 ...]
```

`sample_crt_uniform_binary_values*`、`sample_crt_sparse_ternary_values*` 和 `sample_crt_gaussian_values*` 在每个分量中编码同一个逻辑系数；`sample_crt_uniform_values*` 则按各分量的 uniform 分布独立采样。

调用方须提供完整分块与精确分量数；非空批次的长度须非零。CRT uniform-binary 采样特别要求至少一个非空块，不完整尾块不会被填充。其他 helper 的空输入与长度条件见 [CRT 采样 API](src/common/crt.rs)。

CRT Gaussian helper 不检查各模数能否编码完整截断支持集。对于标准差 `sigma` 和 tail cut `tau`，每个模数必须大于 `max(1, floor(sigma * tau))`；facade 使用 `tau = 12`。

## 统计诊断

`stats` 模块提供：

- `gaussian_stats`：将规范 modular 样本转换为居中代表元，并计算 mean、population standard deviation 和累计 magnitude count；
- `theoretical_cumulative_probs`：计算对应截断离散 Gaussian 的理论累计概率。

这些函数用于测试和验证工具，而不是采样热路径。其 rustdoc 记录了精确的浮点数与模数 限制。

## High-precision feature

可选的 `high_precision` feature 提供 `PreciseCDTSampler` 和 `SignedPreciseCDTSampler`。它们使用 256-bit CDT threshold，并支持比 portable CDT backend 更大的表；facade 类型不会自动选择这些 backend。

## 测试与 benchmark

```text
cargo test -p primus_distr
cargo bench -p primus_distr --bench gen_sampler
cargo bench -p primus_distr --bench sample_gaussian
cargo bench -p primus_distr --bench sample_secret_key
```

## 许可证

本 crate 可由你选择使用 [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) 或 [MIT License](../../LICENSE-MIT)。
