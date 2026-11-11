# primus_tfhe_glwe_fourier

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

基于原生环面和 Fourier 变换的 GLWE TFHE 后端。提供 PBS、ManyLUT、分解式 MVB、Boolean 门和 CBS，两种 PBS 顺序均支持 Classic binary/ternary 或直接 block binary 盲旋转。见[操作与编码选择](../primus_tfhe/README.zh_CN.md#选择同态操作)和 [GLWE 参数/密钥域](../primus_tfhe_glwe/README.zh_CN.md)。

## 快速开始

```sh
cargo run -p primus_tfhe_glwe_fourier --release --example fourier_basic
```

[basic 示例](examples/fourier_basic.rs)将加密输入组合成 `z=2*x+y`，计算 `score=min(z,6)`，再直接对该密文执行第二次 PBS，得到 `price=2*score+[score>=4]`。它使用 `Word = u64`、消息模数 t=32，复用密钥、LUT、evaluator 和缓冲。源码标明客户端/服务端阶段，只解密最终结果。反馈须满足 padded 输入范围及噪声预算，消息模数相同并不足够。

## 实验配套参数

```rust
use primus_tfhe_glwe_fourier::{experimental, TfheContext};
use primus_fft::RustFftTable as Table;

let config = experimental::CLASSIC_PBS_U64;
// Context 使用 config.messages；构造前修改 output_modulus 即可覆盖默认输出域。
let context = TfheContext::<u64, Table>::try_from_pbs_config(config)?;
```

从 [experimental](src/experimental.rs) 选择操作配置。`PbsConfig` 包含 BR/KS、PBS 顺序及输入输出消息；`CbsConfig` 添加 CBS gadget 和输入编码，使用 `TfheContext::try_from_cbs_config`。这些算术教学参数的**安全性及失败概率尚未评估**，数值选择与噪声角色见[家族指南](../primus_tfhe_glwe/README.zh_CN.md#实验配套参数)。

Padded CBS 示例使用 t8 教学配置；MSB 示例显式选择 `CbsInputEncoding::MsbBoolean`（t=2）。基准内的 CMUX2 比较参数采用不同输入和消费契约，不能直接替换。候选范围见[参数筛选说明](../../guides/performance/README.zh_CN.md#tfhe-comparisons)。

`PbsMessageConfig::new(t_in)` 默认输入输出消息模数相同，`.with_output_modulus(t_out)` 可独立修改输出。创建 PBS context 前设置 `config.messages`，CBS 则设置 `config.pbs.messages`；PBS 和 padded CBS 客户端、编译器据此派生编码；MSB Boolean CBS 独立使用 t=2。同钥消息覆盖见[选择输出编码](../primus_tfhe/README.zh_CN.md#选择输出编码)。

## 操作示例

示例均使用 u64，在请求循环外准备可复用状态。替换快速开始命令中的示例名即可运行其他流程。

| 流程 | `experimental` 配置 | 完整示例 |
| --- | --- | --- |
| 两次连续 PBS | `CLASSIC_PBS_U64` | [fourier_basic](examples/fourier_basic.rs) |
| `admin OR (member AND NOT revoked)` | `CLASSIC_PBS_U64`，消息 4→4 | [fourier_boolean](examples/fourier_boolean.rs) |
| ManyLUT grade/flag，再做密文组合 | `CLASSIC_MANY_LUT_U64` | [fourier_many_lut](examples/fourier_many_lut.rs) |
| CBS 谓词 → CMux → 环加法 → LWE | `CLASSIC_CBS_U64` | [fourier_circuit_bootstrap](examples/fourier_circuit_bootstrap.rs) |
| MSB Boolean NOT → 加密服务限额 | `CLASSIC_CBS_U64`，MSB 输入 | [fourier_msb_cbs](examples/fourier_msb_cbs.rs) |
| 同一输入产生 17 个数值阈值标志 | `CLASSIC_THRESHOLD_MVB_U64` | [fourier_mvb_thresholds](examples/fourier_mvb_thresholds.rs) |

普通 PBS/ManyLUT 和 MVB 使用 `context.try_generate_keys(rng)`。从 `client.external_lwe_secret_key()` 取得外部秘密，绑定到 `context.encryptor`；PBS/ManyLUT 用 `pbs_decryptor` 解密，MVB 的 Scaled 输出用 `mvb_decryptor`。公钥输入使用 `public_encryptor`，客户端无需 LUT 或手工 codec。

ManyLUT 通过 `pbs_lookup_table_compiler` / `compile_interleaved_fn` 编译，使用 `context.evaluator` 求值。示例从 t_in=16 映射到 t_out=8，再组合返回的 grade/flag 密文；它们不能直接反馈给编码不同的输入 PBS。MVB 使用 `compile_mvb_fn` 和 `mvb_evaluator`，保留完整输入分辨率，但因子范数会放大噪声。其 Scaled 标志不是 Boolean 门密文，见[共享 MVB 契约](../primus_tfhe/README.zh_CN.md#固定尺度分解式-mvb)。

CBS 输入使用 `cbs_encryptor`（或 `cbs_public_encryptor`），两种输入模式均调用其 `encrypt` / `encrypt_to`。普通 `encryptor` 保持 PBS 编码。CBS 使用 `context.try_generate_circuit_bootstrap_keys(rng)`、`compile_cbs_fn` 和 `circuit_bootstrap_evaluator_with_lookup_table`。示例编译 `[m>=2]`，选择加密费用方案，加上加密附加费用，再将一个系数返回为 LWE。`accumulator_client(client.glwe_secret_key(), t_ring)` 以 Scaled 编码加密候选，候选的 t_ring=8 独立于外部消息域。环系数不是独立 SIMD 槽。CMux 要求整个输入域上的函数均为 bit、秘密配对且候选兼容，见 [CBS 契约](../primus_tfhe/README.zh_CN.md#cbs-输出与消费)。普通 PBS 可复用 CBS 组合中的 `server.server_key()`。

CBS 示例用 `cbs.into_parts()` 和 `Evaluator::try_from_resources` 转交已有缓冲区，CBS/CMux 执行时借用 `evaluator.bootstrap_resources_mut()`。`return_ring_at_to` 返回指定系数，再用 `context.ring_return_decryptor(secret, t_ring)` 按候选环密文的消息模数解码。BR→KS 返回 q 下的小秘密 LWE；KS→BR 在 Q 下直接提取到环秘密。纯环工作流仍可保留自带资源的 CBS evaluator，无需返回 scratch。

启用 `split-trace`（默认开启）后，需要额外的 trace 精度时，在 `TfheContext::try_from_cbs_config(config)` 前设置 `config.fourier_trace_precision = FourierTracePrecision::Split35`。选择保存在 `CbsParameters` 中；绑定已准备参数使用可返回错误的 `TfheContext::try_from_cbs_parameters`。首版支持 native u64、rank-1 binary/ternary 环秘密，普通 trace 保持默认。ordinary 和 Split35 均使用精确系数密钥生成。Split 使 trace key payload 和逆变换次数翻倍；它不修复不足的 BR/SS 分解，也不证明失败概率。同一个 CBS 示例可加 `-- --split-trace`，加密、谓词和 CMux 流程不变。独立组合通过 `circuit_bootstrap::CbsTraceKey` 区分对应的 GLWE trace 表示。

升级时须重新生成旧版未约简 Fourier 路径的求值材料；已公开过此类材料的秘密也应更换。具体表示与噪声限制见 [GLWE 加密契约](../primus_glwe/README.zh_CN.md#加密与解密)，修复前后成本见[建钥性能](../../guides/performance/README.zh_CN.md#fourier-key-generation)。

## 参数与表示

小 LWE 的 BR 输入使用 q（`config.small_lwe.cipher_modulus`），累加器和 ring KS 使用 Q（`config.ring_modulus`）；现有预设采用 q=Q。BR→KS 的外部输入/返回使用 q，KS→BR 的外部输入/返回使用 Q，内部小 LWE 转换到 q。`PbsOrder::BootstrapKeyswitch` 的外部秘密是小 LWE 秘密（维数 n），`KeyswitchBootstrap` 则是展平的环秘密（维数 kN）。`context.allocate_lwe_ciphertext()` 使用所选外部维数。Basic 示例使用 BR→KS，MVB 示例使用 KS→BR。必需 KS 及其独立噪声见[家族指南](../primus_tfhe_glwe/README.zh_CN.md#参数与外部密钥域)。

通过 `PbsConfig<T, LM>` / `TfheContext<T, Table, LM>` 指定独立输入 reducer，例如 q=1024 使用 `LM = PowOf2Modulus<T>`。客户端和程序工厂自动选择对应域。准备后的 evaluator 为 `Evaluator<T, Table>`，不携带输入 reducer 类型，仍绑定原 context 和配对密钥；Boolean 门封装目前要求 q=Q。

本后端的累加环只支持 `NativeModulus<T>`，不支持 `PowOf2Modulus` 环。`RustFftTable` 和 `TfheFftTable` 均支持 u32/u64。

变换域密钥、数据和 evaluator 须使用**同一个 FFT 表实例**，长度相同不能证明表示一致。除加密、分解和密钥切换噪声外，还须计入 FFT 近似误差，详见 [Fourier 契约](../primus_fft/README.zh_CN.md)。

分解式 MVB 要求实际 Scaled 输出尺度 `round(2^BITS/t_out)` 为偶数；奇数尺度返回 `LookupTableError::OddFactorizationScale`。因子按有符号整数变换，不做环面缩放；须预算其放大和 FFT 误差。见 [MVB 契约](../primus_tfhe/README.zh_CN.md#固定尺度分解式-mvb)。

Classic BR 支持固定重量二进制秘密。Block BR 需要设置 `config.method = BlindRotationMethod::Block` 和 `config.small_lwe.secret_key_distr = SecretKeyDistr::BlockBinary { block_size, occupancy }`。`AtMostOne` 允许空块，每块增加一个独立加密的 dummy。`ExactlyOne` 只保存 bit 控制。两种算法均支持两种顺序的 PBS、ManyLUT、MVB 和 CBS。Block 在 native 系数域精确聚合，使用普通 FFT，CBS trace 精度保持独立选择。原始单输入 BR 使用 `block::BlockGlweBlindRotationWorkspace::new(key)` 和 `blind_rotate_lookup_table_to`。迁移和参数要求见 [GLWE 密钥说明](../primus_tfhe_glwe/README.zh_CN.md#盲旋转密钥)。

重复请求保留 context、密钥和已编译程序，`_to` 方法复用 evaluator scratch 及调用方输出；并发请求需要独立的可变 evaluator。MVB 程序保持与其 context 绑定。`KeyGenerator::try_generate_blind_rotation_key(client, rng)` 根据 context 的 `config.method` 仅生成 BR 材料；独立组件须使用相同的实际秘密和变换表示。独立材料组合及逐调用借用契约见 [KeyGenerator](src/key.rs)、[Evaluator](src/evaluator.rs) 和 [CircuitBootstrapEvaluator](src/circuit_bootstrap/evaluator.rs)，默认流程无需手工组合资源。借用资源执行 CBS 时，先编译程序，再通过 `CircuitBootstrapEvaluator::try_new` 绑定所选 gadget 参数与 circuit key。

## Features

默认启用 RustFFT 和 `split-trace`，默认 trace 表示仍为 ordinary。`split-trace` 增加 Split35 能力。底层 GLWE Fourier feature 包含系数建钥使用的内部辅助 NTT/CRT 依赖，与 trace 表示的选择无关。可选 `simd` 启用依赖中的 nightly SIMD 算术，不选择 FFT 引擎。

| Cargo 参数 | 可用引擎 | Trace 能力 |
| --- | --- | --- |
| 默认 | RustFFT | Ordinary + Split35 |
| `--features tfhe-fft` | 两者均可用，由具体表类型选择 | Ordinary + Split35 |
| `--no-default-features --features rustfft` | RustFFT | Ordinary |
| `--no-default-features --features tfhe-fft` | TFHE-FFT | Ordinary |
| `--no-default-features --features tfhe-fft,split-trace` | TFHE-FFT | Ordinary + Split35 |
| `--no-default-features` | 不含具体引擎的泛型 API | Ordinary |

示例导入 `primus_fft::RustFftTable as Table`，并在 [Cargo.toml](Cargo.toml) 声明 `required-features = ["rustfft"]`；只添加 `--features tfhe-fft` 不会切换引擎。仅用 TFHE-FFT 运行示例时，须将导入改为 `primus_fft::TfheFftTable as Table`，对应 target 的 `required-features` 改为 `["tfhe-fft"]`，再使用 `--no-default-features --features tfhe-fft`。

基准已经分别实例化每个启用的引擎，选择引擎无需修改基准源码。关闭默认 features 后，若示例或基准还需提供 Split35，应另加 `split-trace`；否则 `cbs_identity` 只注册 ordinary 用例。

## 基准

```sh
cargo bench -p primus_tfhe_glwe_fourier --bench pbs
```

| Target | 计时请求 |
| --- | --- |
| [pbs](benches/pbs.rs) | 一次完整 PBS；dense Classic u32/u64；显式 Low/High 比较组见[测试指南](../../guides/development/testing.md#tfhe-benchmarks) |
| [modulus_domains](benches/modulus_domains.rs) | q=Q/q1024 的两种顺序完整 PBS；用 `PRIMUS_DOMAIN_CASE=same/bk`、`split/bk`、`same/kb` 或 `split/kb` 选择；要求 `tfhe-fft` |
| [many_lut](benches/many_lut.rs) | 一次双输出 grade/flag ManyLUT，u64 |
| [mvb](benches/mvb.rs) | 一次 17 输出阈值 MVB，u64 |
| [cbs](benches/cbs.rs) | 一次谓词 CBS、CMux 和单系数 LWE 返回，u64 |
| [cbs_identity](benches/cbs_identity.rs) | 含输入 ring KS 的 identity CBS → Fourier GGSW 或 CBS＋CMux；派生 CMUX2/CMUX3、ordinary/split35、padded/MSB、bit 0/1、u64 |

每次迭代使用已准备的密钥、LUT 和缓冲测量一个服务端请求，准备和解密校验不计时。ManyLUT/CBS 基准不包含示例后续的密文算术。计时范围与比较限制见[基准指南](../../guides/development/testing.md#tfhe-benchmarks)。

仅测量 TFHE-FFT：

```sh
cargo bench -p primus_tfhe_glwe_fourier --bench pbs --no-default-features --features tfhe-fft
```

保留默认 features 并添加 `--features tfhe-fft`，可分别测量两个引擎。

identity 基准在计时前检查 bit 0/1 的真实单层 CMux 消费；验证失败直接报错。
不采样地运行两个引擎：

```sh
cargo bench -p primus_tfhe_glwe_fourier --bench cbs_identity --features tfhe-fft -- --test
```

其 unsigned t4 编码、ring KS 和 reverse trace 与作者协议不同，
见[参数映射](../../guides/performance/README.zh_CN.md#tfhe-comparisons)。

## 进一步阅读

[API 源码](src/lib.rs) · [共享编码与错误](../primus_tfhe/README.zh_CN.md) · [数值契约](../../guides/development/bootstrapping-contracts.md) · [性能说明](../../guides/performance/README.zh_CN.md)
