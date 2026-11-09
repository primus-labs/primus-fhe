# primus_lwe

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

Primus FHE 的单模数 LWE 密钥生成、私钥加密、公钥加密和密钥切换实现。密文存储与算术来自 [`primus_lattice`](../primus_lattice/README.zh_CN.md)，消息编码使用 [`RoundedCodec`](../primus_encoding/README.zh_CN.md)。

## API

公开类型均从 crate 根导出。

| 类型 | 职责 |
| --- | --- |
| `LweConfig<M>` | 可用于常量定义的数值描述，通过 `TryFrom` 转为已准备的加密参数 |
| `LweEncryptionParameters<T, M>` | 密文域与预计算采样器，不含消息 codec |
| `LweParameters<T, M>` | 维度、模数、明文 codec、私钥分布及预计算采样器 |
| `LweSecretKey<T>` | 持有 Encoded 系数；提供 message、encoded 和 phase 操作 |
| `LweSecretKeyRef<'a, T>` | 借用 `Encoded` 或 `Signed` 系数；提供单条密文的 raw 操作 |
| `LwePublicKey<T>` | 方阵 Lindner–Peikert 风格的公钥加密 |
| `LweKeySwitchingParameters<T, M>` | 目标加密状态与匹配的分解基 |
| `LweKeySwitchingKey<T>` | 在相同密文模数下切换私钥，允许改变维度 |
| `LweCiphertext<T>` | `primus_lattice::lwe::Lwe<Vec<T>>` 的别名 |
| `MultiMsgLweCiphertext<T>` | `primus_lattice::lwe::MultiMsgLwe<Vec<T>>` 的别名 |

`encrypt_message` / `encrypt_message_batch` 显式接收 `PlaintextEmbedding` 并分配输出；对应的 `_to` 接口覆盖调用方提供的存储， 不进行分配。私钥解密接受拥有或借用存储的密文。公钥密文使用相同的解密和密钥切换接口。

## 快速开始

先使用 message 接口完成加密/解密；只有需要自行控制编码或读取 phase 时才使用原语接口。以下小参数仅展示用法，不是安全参数。调用方直接依赖 `primus_lwe`、`primus_modulus`、`primus_encoding` 和 `rand`。

```rust
use primus_encoding::PlaintextEmbedding;
use primus_lwe::{LweDimension, LweParameters, LweSecretKey, SecretKeyDistr};
use primus_modulus::NativeModulus;

let params = LweParameters::new(
    LweDimension::new(64),
    4u64,
    NativeModulus::new(),
    SecretKeyDistr::UniformBinary,
    0.7,
);
let mut rng = rand::rng();
let secret = LweSecretKey::generate(params.encryption_parameters(), &mut rng);
let embedding = PlaintextEmbedding::Unsigned;
let message = 3;

// 普通消息：适配层使用参数中的 codec。
let mut ciphertext = secret.encrypt_message(message, &params, embedding, &mut rng);
assert_eq!(secret.decrypt_message(&ciphertext, &params), message);

// 编码原语：单独选择编码，并复用密文存储。
let codec = params.plaintext_codec();
let encoded = codec.encode_value(message, embedding);
secret.encrypt_encoded_to(
    encoded,
    &mut ciphertext,
    params.encryption_parameters(),
    &mut rng,
);
let phase = secret.decrypt_phase(&ciphertext, params.cipher_modulus());
assert_eq!(codec.decode_value(phase), message);
```

[examples/basic.rs](examples/basic.rs) 展示公钥、独立 batch 与密钥切换：`cargo run -p primus_lwe --example basic`。重复请求复用密钥与参数，使用 `encrypt_message_to` / `encrypt_encoded_to` 复用输出。

## 参数与编码

`LweConfig<M>` 保存维数、`primus_modulus::ModulusConfig<M>`、秘密分布和系数噪声标准差。使用 `LweEncryptionParameters::try_from(config)` 验证模数并一次准备采样器。`LweConfigError` 区分模数配置错误与 `LweParameterError`；模数已准备时仍可直接使用参数构造器。

普通消息流程使用 `LweParameters`，其中包含 `RoundedCodec`；只处理已编码数据时使用不含 codec 的 `LweEncryptionParameters`。生成私钥传入 `params.encryption_parameters()`，拥有型 `encrypt_encoded[_to]` 也使用该参数类型。`decrypt_phase` 接收密文与模数，返回 `b - <a,s>`，不执行解码。

`LweDimension::try_new(n)` 检查非零 `n` 和可表示的 `n+1`；`.ciphertext_len()` 用于分配存储。`LweParameters::try_new` 检查编码、秘密分布与噪声条件，失败返回 `LweParameterError`，`new` 在相同错误下 panic。要求 `t >= 2`、`q > t`，固定秘密重量不得超过 `n`。`NativeModulus<T>` 表示 `q = 2^T::BITS`，对应的 `cipher_modulus_value()` 返回 `None`；显式模数返回 `Some(q)`。噪声标准差以密文系数为单位。

消息输入和解码输出均为 `[0,t)` 中的 `T`。`PlaintextEmbedding::Centered` 也接受无符号剩余类，例如 `t-1` 表示 `-1`；两种 embedding 共用 `decrypt_message`。私钥加密满足 `b = <a,s> + e + Encode(message) mod q`，相位噪声须处于 codec 的解码余量内。

私钥、密文和参数须具有相同维数与模数，Encoded 系数须为规范剩余。拥有型密钥检查记录的模数；`LweSecretKey::new(coefficients, distribution, modulus)` 还要求导入系数符合声明的分布，但不检查这些系数条件。私钥系数在 drop 时擦除；显式 `zeroize()` 后应丢弃密钥。

`as_view()` 不携带模数元数据，用于 raw 接口前须先确认拥有型密钥的模数。借用型 `encrypt_encoded[_to]` 接收已编码剩余类、模数、均匀/噪声采样器和 RNG；采样器必须使用相同模数。`LweSecretKeyRef::Signed` 无需转换副本即可借用有符号系数：显式模数下要求 `-q < s_i < q`，Native 下允许所有有符号值。原始视图允许零维。

诊断噪声时，用实际 codec 和 embedding 编码**预期消息**，通过 [`phase_error_magnitude`](../primus_encoding/README.zh_CN.md#相位误差诊断) 与提取的 phase 比较。它返回圆周距离；将解码结果重新编码作为参考可能掩盖错误解密。

## 公钥加密

`LwePublicKey::generate(secret, dimension, modulus, uniform, noise, rng)` 接收 `LweSecretKeyRef` 和已准备的采样器。拥有型私钥传入 `secret.as_view()`，有符号秘密可传入 `LweSecretKeyRef::Signed`；先按上述约定确认秘密和采样器的模数。

消息加密使用 `encrypt_message[_to]`、`LweParameters` 与显式 embedding；已编码加密使用 `encrypt_encoded[_to]`、模数、噪声采样器和 RNG。所得密文使用同一套私钥解密和密钥切换接口。

公钥保存 `n` 行 `[A_i, b_i]`，共 `n*(n+1)` 个系数，满足 `b = A s + e`。加密采样独立的三元系数 `r`，其中 `Pr[0] = 1/2`、`Pr[-1] = Pr[1] = 1/4`，以及新的高斯噪声 `e1, e2`：

```text
a = A^T r + e1
c = b^T r + e2 + Encode(message)
phase = Encode(message) + e^T r + e2 - e1^T s  (mod q)
```

加密时的噪声采样器描述 `e1`、`e2`，不代表总噪声。参数须同时考虑长期与临时秘密的安全性、全部噪声项及解密失败概率；私钥加密参数不能直接视为适合公钥加密。当前实现只检查维数和模数身份。这是 CPA 加密原语，不包含 KEM 或 CCA 变换；临时系数参与分支，当前实现并非恒定时间。

## 独立 batch 与 packed 消息

独立 batch 连续存放 `count` 条 `[a,b]`，每条长 `n+1`，条数不受 `n` 限制。用 `LweIter` / `LweIterMut` 借用单条密文；迭代器会忽略不完整尾部，而 LWE batch 入口会拒绝这种输入。

- `encrypt_message_batch_to` 的输出恰好包含 `messages.len()*(n+1)` 个元素；`decrypt_message_batch_to` 每条密文写出一个消息。
- 已编码与相位接口为 `encrypt_encoded_batch[_to]`、`decrypt_phase_batch[_to]`。私钥 batch 要求拥有型 `LweSecretKey<T>`；Signed 视图只支持单条 raw 操作。私钥已编码 batch 与单条加密一样接收 `&LweEncryptionParameters`；密钥必须匹配其非零维数和模数。
- 空的独立 batch 不消耗随机数。RNG 顺序不保证与逐条加密一致，固定 seed 也不保证跨版本密文字节相同。
- Batch 入口先检查完整长度；非法消息或 RNG panic 可能留下部分输出并消耗随机数。

Packed 加密用一个长度为 `n` 的共享 mask 和 `count <= n` 个 body，共 `n+count` 个系数。第 `i` 个 body 使用 mask 右移 `i` 位、前 `i` 项取负后的掩码；这些样本不是独立 mask。使用 `encrypt_message_packed` / `decrypt_message_packed` 或 `MultiMsgLwe::extract_lwe_at`，不能直接用 `LweIter` 遍历其中的样本。已编码与相位接口为 `encrypt_encoded_packed`、`decrypt_phase_packed`；加密零消息时传入全零的已编码切片。空 packed 消息列表仍采样并保存共享 mask。

## 密钥切换

用 `LweKeySwitchingParameters::try_new(output, basis)` 组合拥有型 `LweEncryptionParameters` 和同模数的 `ApproxSignedBasis`。其中的噪声采样器用于加密密钥条目，可以不同于新鲜消息加密的噪声。再将 `&parameters`、Encoded/Signed 输入私钥视图和拥有型输出私钥传给 `LweKeySwitchingKey::generate`。密钥包含 `input_dimension * levels * (output_dimension+1)` 个系数。

`key_switch[_to]` 处理单条密文，`key_switch_batch[_to]` 处理独立 batch；输入、输出可以有不同维数，但须使用相同密文模数与消息编码。密钥切换不执行模数切换或重编码，噪声预算须包含分解误差和密钥条目噪声。Batch 与逐条切换的结果逐系数一致；`_to` 接口复用输出，不需要堆上临时工作区。

## Feature 与基准

默认 features 为空；`simd` 启用底层库的 nightly SIMD 算术。公开契约见 [API 源码](src/lib.rs)，验证命令见 workspace [测试指南](../../guides/development/testing.md)。

三个基准分别测量私钥加密/相位提取（含复用与 packed）、公钥生成/加密，以及密钥切换生成/求值。在 workspace 根目录运行：

```sh
cargo bench -p primus_lwe --bench secret_key
cargo bench -p primus_lwe --bench public_key
cargo bench -p primus_lwe --bench key_switch
```
