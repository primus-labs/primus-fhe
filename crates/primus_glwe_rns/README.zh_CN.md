# primus_glwe_rns

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

有序 RNS 基上的 GLWE 加密与求值，分别使用 CRT 系数表示和 DCRT NTT 表示。提供 BFV 尺度加密、gadget 乘法、自同构、trace、展开与密钥切换等构建模块，不是完整的 BFV/BGV/CKKS 方案。

## 推荐流程

1. 选择有序、两两互素的 NTT 素数，构造一个 `DcrtTable`；每个素数须满足 [NTT 条件](../primus_ntt/README.zh_CN.md#构造约束)。
2. 用维数 k、多项式长度 N、明文模数 t、辅助解码模数 gamma、有序密文模数、秘密分布和噪声构造 `CrtGlweParameters`。需要处理无效配置时使用 `try_new`；其 [`BfvRnsCodec`](../primus_encoding/README.zh_CN.md#bfv-rns) 提供缩放与恢复检查。
3. 生成有符号系数 `GlweSecretKey`，通过 `DcrtGlweSecretKey::from_coeff_secret_key` 转换，用 `try_bind(&parameters, &table)` 绑定一次，之后使用返回的 `DcrtGlweSecretKeyContext`。
4. 用参数的长度访问器分配密文，复用输出及 `DcrtGlweDecryptWorkspace`；`decrypt_to` 还复用调用方的明文输出。

下面的小参数用于演示系数加密和存储复用，不代表安全参数。片段需要直接依赖 `primus_glwe_rns`、`primus_lattice`、`primus_modulus`、`primus_ntt`、`primus_poly` 和 `rand`：

```rust
use primus_glwe_rns::{
    CrtGlweParameters, DcrtGlweCiphertext, DcrtGlweDecryptWorkspace,
    DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr,
};
use primus_modulus::BarrettModulus;
use primus_ntt::UintDcrtTable;
use primus_poly::Polynomial;
use primus_shape::PolyLength;

let moduli = [998_244_353u32, 1_004_535_809].map(BarrettModulus::new);
let poly_length = PolyLength::new(32);
let table = UintDcrtTable::new(poly_length, &moduli).unwrap();
let parameters = CrtGlweParameters::new(
    primus_lattice::GlweDimension::new(2), poly_length, BarrettModulus::new(17), BarrettModulus::new(65_537),
    &moduli, SecretKeyDistr::UniformBinary, 3.2,
);
let mut rng = rand::rng();
let coefficient_key = GlweSecretKey::generate(
    parameters.size().glwe_size(), parameters.secret_key_sampler(), &mut rng,
);
let key = DcrtGlweSecretKey::from_coeff_secret_key(&coefficient_key, &table);
let mut ciphertext = DcrtGlweCiphertext::<Vec<u32>>::zero(parameters.rns_glwe_len());
let mut workspace = DcrtGlweDecryptWorkspace::new(parameters.size());
let message = Polynomial::new(vec![3u32; parameters.poly_length().get()]);

let context = key.try_bind(&parameters, &table).unwrap();
context.encrypt_to(&message, &mut ciphertext, &mut rng);
let decoded = context.decrypt(&ciphertext, &mut workspace);
assert_eq!(decoded.as_ref(), message.as_ref());
```

## 编码与表示

设 `Q = product_i q_i`。普通加密施加 BFV 缩放 `floor(Q/t)`，gadget 加密使用自己的分解基，不做 BFV 缩放。

| 私钥 context 方法 | 输入或结果 |
| --- | --- |
| `encrypt_to` / `encrypt_centered_to` | N 个 `[0,t)` 中的规范消息，分别使用 unsigned / centered 提升 |
| `encrypt_plaintext_crt_to` | 约简到各 `[0,q_i)` 的未缩放明文提升；施加 BFV 缩放 |
| `encrypt_zeros_to` | 零加密 |
| `phase_to` | DCRT 相位，不恢复系数或解码 |
| `decrypt` / `decrypt_to` | 解码后的系数多项式；分配 / 复用明文输出 |

加密覆盖 DCRT 输出。**不要将 codec 已缩放的输出传给 `encrypt_plaintext_crt_to`**，否则会重复缩放。`DcrtGlwePublicKeyContext::encrypt_plaintext_crt` 对同样的未缩放 CRT 提升进行公钥加密并分配输出，其噪声包含额外的公钥贡献。

m 个模数下，普通密文包含 `(k+1)*m*N` 个元素，顺序为 `[component][modulus][coefficient/evaluation]`；gadget 在外层增加 row/level。CRT 与 DCRT 形状相同，算术含义不同。使用 `RnsGlweSize` / `RnsGadgetSize` 及语义迭代器，始终保持模数顺序。见[密文布局](../primus_lattice/README.zh_CN.md#存储与布局)。

## 参数组合

| 参数 | 用途 |
| --- | --- |
| `CrtGlweParameters` | 普通 BFV 加解密，包含 t、gamma 和恢复条件 |
| `CrtGlweEncryptionParameters` | 布局、有序模数及采样器；无明文 codec |
| `CrtGlevParameters` | 加密参数及乘积模数 Q 下的 gadget 分解；无 BFV 缩放 |

维数和环长度使用 `GlweDimension` 与 [PolyLength](../primus_shape/README.zh_CN.md#多项式长度)，分解使用 `DecompositionBaseLog` / `DecompositionLevelCount`，在参数、尺寸和表之间复用这些已验证值。固定秘密重量作用于完整 kN 个有符号系数，不是逐多项式或逐 RNS limb 应用。秘密和噪声幅度须小于每个 q_i，噪声标准差以系数为单位。

已有普通参数时，`CrtGlevParameters::try_with_glwe_params` 派生同一有序基下的 gadget 参数。仅需 gadget 时无需 t 或 gamma，构造方式见 [`CrtGlevParameters::try_from_parts`](src/parameter/gadget.rs)。分解基须匹配 Q 及其定宽 limb 表示，radix 须严格小于每个 q_i。密钥角色需要不同噪声分布时，应分别准备加密参数。

普通参数构造将采样器的最大噪声幅度传给 `BfvRnsCodec::validate_noise_bound`。Unsigned 提升检查也覆盖 centered 提升，为**新鲜私钥加密**建立恢复条件；余量不足返回 `CrtGlweParametersError::Encoding`。公钥加密及同态求值仍需完整相位噪声界。构造不证明 NTT 可用性或安全等级。

## 求值资源

普通私钥/公钥使用 `try_bind(&parameters, &table)`。Gadget 使用 `DcrtGadgetDomain::try_new(&gadget, &table)`，再调用 `try_bind_gadget(&domain)`：私钥返回 `DcrtGlevEncryptor`，公钥返回 `DcrtGgswEncryptor`。GLev 的 `encrypt_crt_to` / `encrypt_dcrt_to` 接收系数 / NTT 消息并施加 gadget 权重；GGSW 的 `encrypt_monomial_ggsw` / `encrypt_monomial_ggsw_to` 分别分配 / 复用输出。

Client 生成公钥及求值密钥并交给 server。公钥和 key-switch 密钥生成使用无 codec 的 `encryption_parameters()`。从密钥及 domain 构造一次 evaluator，在线调用复用其自身 scratch。绑定检查资源布局、有序基及相应分解参数；输入输出布局、规范剩余类、NTT 根/顺序、秘密身份和足够的噪声余量仍由调用方保证。

例如，接着上述加密流程使用（另需直接依赖 `primus_decompose`）：

```rust
use primus_decompose::DecompositionBaseLog;
use primus_glwe_rns::{CrtGlevParameters, DcrtGadgetDomain, DcrtGlweAutoEvaluator, DcrtGlweAutoKey};

let gadget = CrtGlevParameters::with_glwe_params(&parameters, DecompositionBaseLog::new(8), None);
let domain = DcrtGadgetDomain::try_new(&gadget, &table).unwrap();
let auto_key = DcrtGlweAutoKey::new(&domain, 3, &key, &mut rng);
let mut evaluator = DcrtGlweAutoEvaluator::try_new(&auto_key, &domain).unwrap();
let mut output = DcrtGlweCiphertext::<Vec<u32>>::zero(parameters.rns_glwe_len());
evaluator.automorphism_to(&ciphertext, &mut output);
```

`CrtGlweAutoEvaluator` 使用系数密文，`DcrtGlweAutoEvaluator` 使用 NTT 密文，两者均返回原秘密下的结果。

| Key-switch evaluator | Domain |
| --- | --- |
| `DcrtGlweKeySwitchEvaluator` | 有序 Q 上的 `DcrtGadgetDomain`，gadget 布局及 radix 匹配 |
| `HybridRnsGlweKeySwitchEvaluator` | 有序 QP 上的 `HybridRnsKeySwitchDomain`，N、Q/P 分界及分区宽度匹配 |

两者均提供 `try_new(&key, &domain)`，在线调用为 `key_switch_to(&input, &mut output)`。Hybrid 密钥生成从输入加密参数取得密钥噪声，检查其支持范围是否适用于每个 QP 模数；两个秘密的幅度也必须小于每个 QP 模数。分区及 ModUp/ModDown 契约见 [`primus_rns`](../primus_rns/README.zh_CN.md#hybrid-rns)。

## Trace 与系数展开

这些 evaluator 借用密钥和 gadget domain，并拥有可复用 scratch。输入保持不变，输出及 scratch 被覆盖。下表目标消息省略求值误差。

| Evaluator 及方法 | 目标消息 |
| --- | --- |
| `CrtGlweTraceEvaluator` / `DcrtGlweTraceEvaluator`，`trace_to` | 常数 `N*m[0]` |
| `DcrtGlweRevTraceEvaluator`，`trace_to` | 常数 `m[0]` |
| CRT/DCRT 的 `expand_coefficients_to` | 恰好 N 个输出，第 j 个目标为常数 `m[j]` |
| CRT/DCRT 的 `expand_partial_coefficients_to` | 数量为 `1..=N` 内二次幂，消息尾部为零时目标为前缀各系数对应的常数 |

Reverse trace 在每次自同构及相加前乘 `2^-1 mod q_i`，保持 Q 和环长度；这是模除法，不是 modulus switch 或舍入减半。完整序列将输入消息和输入误差投影到常数项，但较晚引入的 key-switch 误差可能留在非常数位置。不能从无舍入推出 native-torus 方差界，详见[相位与误差契约](src/dcrt/rev_trace.rs)。

展开没有额外的 count 倍数。部分展开要得到常数，被省略的**明文**系数必须为零，否则它们仍保留在 X 的高次项中。密文和噪声尾部无需为零，环长度仍为 N。完整布局与表示条件见 [CRT](src/crt/expand_coeff/evaluator.rs) 和 [DCRT](src/dcrt/expand_coeff/evaluator.rs) evaluator。

串行展开使用 `*GlweExpandCoeffEvaluator::new(&key, &domain)`，预分配并行池使用 `*GlweExpandCoeffParallelEvaluator::new(&key, &domain, worker_count)`。串行求值只需一份工作区，并行求值为每个 worker 预留一份；重复调用复用算术 scratch。

并行调用使用 Rayon。求值前初始化线程池，选择正数 `worker_count`，覆盖最多同时工作的 worker 数；自定义池可用其 `current_num_threads()`。调用可变借用 evaluator；scratch 池容量不足可能**在部分输出写入后 panic**。完整使用条件见 evaluator 方法。

## Feature 与进一步阅读

默认 features 为空，`simd` 向算术依赖转发 nightly SIMD。本 crate 已启用所需的 RNS features，无需另设 `rns` 开关。

[公开 API 源码](src/lib.rs) · [RNS 基与转换](../primus_rns/README.zh_CN.md) · [库使用导航](../../guides/development/README.zh_CN.md) · [测试指南](../../guides/development/testing.md)
