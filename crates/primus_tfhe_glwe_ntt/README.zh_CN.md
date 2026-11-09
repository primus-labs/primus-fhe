# primus_tfhe_glwe_ntt

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

基于显式域模数和 NTT的 GLWE TFHE 后端。提供 PBS、ManyLUT、分解式 MVB、Boolean 门和 CBS，两种 PBS 顺序均支持 classic binary/ternary 或 sparse fixed-weight binary 盲旋转。见[操作与编码选择](../primus_tfhe/README.zh_CN.md#选择同态操作)和 [GLWE 参数/密钥域](../primus_tfhe_glwe/README.zh_CN.md)。

## 快速开始

```sh
cargo run -p primus_tfhe_glwe_ntt --release --example ntt_basic
```

[basic 示例](examples/ntt_basic.rs)将加密输入组合成 `z=2*x+y`，计算 `score=min(z,6)`，再直接对该密文执行第二次 PBS，得到 `price=2*score+[score>=4]`。它使用 `Word = u64`、消息模数 t=32，复用密钥、LUT、evaluator 和缓冲。源码标明客户端/服务端阶段，只解密最终结果。反馈须满足 padded 输入范围及噪声预算，消息模数相同并不足够。

## 实验配套参数

```rust
use primus_tfhe_glwe_ntt::{experimental, TfheContext};
use primus_ntt::U64NttTable as Table;

let config = experimental::CLASSIC_PBS_U64;
// Context 使用 config.messages；构造前修改 output_modulus 即可覆盖默认输出域。
let context = TfheContext::<u64, Table>::try_from_pbs_config(config)?;
```

从 [experimental](src/experimental.rs) 选择操作配置。`PbsConfig` 包含 BR/KS、PBS 顺序及输入输出消息；`CbsConfig` 添加 CBS gadget、输入编码和 trace 精度，使用 `TfheContext::try_from_cbs_config`。NTT 必须设置 `fourier_trace_precision: FourierTracePrecision::Ordinary`，参数准备会拒绝 Split35。这些是算术教学参数，**不是经过安全性或失败概率认证的预设**，数值选择与噪声角色见[家族指南](../primus_tfhe_glwe/README.zh_CN.md#实验配套参数)。

`CLASSIC_CBS_U64` 使用 n866/N2048、独立 binary 秘密、两层 BR 和三层 trace/SS。返回 KS 使用小 LWE 的标准差，与环密钥行的标准差不同。已测消费者及评估边界见[参数目录](../../guides/development/tfhe-parameters.md#noise-by-key-role)。

Padded CBS 示例使用 t8 教学配置；MSB 示例显式选择 `CbsInputEncoding::MsbBoolean`（t=2）。基准内的 LightFHE G1 比较参数采用不同输入和消费契约，不能直接替换。候选范围见[参数筛选说明](../../guides/performance/bootstrap-functional-comparison.md)。

`PbsMessageConfig::new(t_in)` 默认输入输出消息模数相同，`.with_output_modulus(t_out)` 可独立修改输出。创建 PBS context 前设置 `config.messages`，CBS 则设置 `config.pbs.messages`；PBS 和 padded CBS 客户端、编译器据此派生编码；MSB Boolean CBS 独立使用 t=2。同钥消息覆盖见[选择输出编码](../primus_tfhe/README.zh_CN.md#选择输出编码)。

## 操作示例

示例均使用 u64，在请求循环外准备可复用状态。替换快速开始命令中的示例名即可运行其他流程。

| 流程 | `experimental` 配置 | 完整示例 |
| --- | --- | --- |
| 两次连续 PBS | `CLASSIC_PBS_U64` | [ntt_basic](examples/ntt_basic.rs) |
| `admin OR (member AND NOT revoked)` | `CLASSIC_PBS_U64`，消息 4→4 | [ntt_boolean](examples/ntt_boolean.rs) |
| 使用 sparse BR 的相同评分流程 | `SPARSE_PBS_U64` | [ntt_sparse](examples/ntt_sparse.rs) |
| ManyLUT grade/flag，再做密文组合 | `CLASSIC_MANY_LUT_U64` | [ntt_many_lut](examples/ntt_many_lut.rs) |
| CBS 谓词 → CMux → 环加法 → LWE | `CLASSIC_CBS_U64` | [ntt_circuit_bootstrap](examples/ntt_circuit_bootstrap.rs) |
| MSB Boolean NOT → 加密服务限额 | `CLASSIC_CBS_U64`，MSB 输入 | [ntt_msb_cbs](examples/ntt_msb_cbs.rs) |
| 独立 q/Q、两种 PBS 顺序 | 示例内显式配置 | [ntt_two_moduli](examples/ntt_two_moduli.rs) |
| 使用 sparse BR 的相同 CBS 流程 | `SPARSE_CBS_U64` | [ntt_sparse_circuit_bootstrap](examples/ntt_sparse_circuit_bootstrap.rs) |
| 同一输入产生 17 个数值阈值标志 | `CLASSIC_THRESHOLD_MVB_U64` | [mvb_thresholds](examples/mvb_thresholds.rs) |

普通 PBS/ManyLUT 和 MVB 使用 `context.try_generate_keys(rng)`。从 `client.external_lwe_secret_key()` 取得外部秘密，绑定到 `context.encryptor`；PBS/ManyLUT 用 `pbs_decryptor` 解密，MVB 的 Scaled 输出用 `mvb_decryptor`。公钥输入使用 `public_encryptor`，客户端无需 LUT 或手工 codec。

ManyLUT 通过 `pbs_lookup_table_compiler` / `compile_interleaved_fn` 编译，使用 `context.evaluator` 求值。示例从 t_in=16 映射到 t_out=8，再组合返回的 grade/flag 密文；它们不能直接反馈给编码不同的输入 PBS。MVB 使用 `compile_mvb_fn` 和 `mvb_evaluator`，保留完整输入分辨率，但因子范数会放大噪声。其 Scaled 标志不是 Boolean 门密文，见[共享 MVB 契约](../primus_tfhe/README.zh_CN.md#固定尺度分解式-mvb)。

CBS 输入使用 `cbs_encryptor`（或 `cbs_public_encryptor`），两种输入模式均调用其 `encrypt` / `encrypt_to`。普通 `encryptor` 保持 PBS 编码。CBS 使用 `context.try_generate_circuit_bootstrap_keys(rng)`、`compile_cbs_fn` 和 `circuit_bootstrap_evaluator_with_lookup_table`。示例编译 `[m>=2]`，选择加密费用方案，加上加密附加费用，再将一个系数返回为 LWE。`accumulator_client(client.glwe_secret_key(), t_ring)` 以 Scaled 编码加密候选，候选的 t_ring=8 独立于外部消息域。环系数不是独立 SIMD 槽。CMux 要求整个输入域上的函数均为 bit、秘密配对且候选兼容，见 [CBS 契约](../primus_tfhe/README.zh_CN.md#cbs-输出与消费)。普通 PBS 可复用 CBS 组合中的 `server.server_key()`。

CBS 示例用 `cbs.into_parts()` 和 `Evaluator::try_from_resources` 转交已有缓冲区，CBS/CMux 执行时借用 `evaluator.bootstrap_resources_mut()`。`return_ring_at_to` 返回指定系数，再用 `context.ring_return_decryptor(secret, t_ring)` 按候选环密文的消息模数解码。BR→KS 返回 q 下的小秘密 LWE；KS→BR 在 Q 下直接提取到环秘密。纯环工作流仍可保留自带资源的 CBS evaluator，无需返回 scratch。

## 参数与表示

小 LWE 的 BR 输入使用 q（`config.small_lwe.cipher_modulus`），累加器和 ring KS 使用 Q（`config.ring_modulus`）；现有预设采用 q=Q。BR→KS 的外部输入/返回使用 q，KS→BR 的外部输入/返回使用 Q，内部小 LWE 转换到 q。`PbsOrder::BootstrapKeyswitch` 的外部秘密是小 LWE 秘密（维数 n），`KeyswitchBootstrap` 则是展平的环秘密（维数 kN）。`context.allocate_lwe_ciphertext()` 使用所选外部维数。Basic 示例使用 BR→KS，MVB 示例使用 KS→BR。必需 KS 及其独立噪声见[家族指南](../primus_tfhe_glwe/README.zh_CN.md#参数与外部密钥域)。

通过 `PbsConfig<T, LM>` / `TfheContext<T, Table, LM>` 指定独立输入 reducer，例如 q=1024 使用 `LM = PowOf2Modulus<T>`。客户端和程序工厂自动选择对应域。准备后的 evaluator 为 `Evaluator<T, Table>`，不携带输入 reducer 类型，仍绑定原 context 和配对密钥；Boolean 门封装目前要求 q=Q。

本后端使用 `BarrettModulus<T>`，显式素数 q 须存在本原 `2N` 次单位根。内置 `U32NttTable` / `U64NttTable` 分别要求 q 小于 `2^30` / `2^62`；素性仍由调用方保证。详见 [NTT 表要求](../primus_ntt/README.zh_CN.md#构造约束)。

自定义表须实现 `MonomialNttTable`。Context 构造检查长度和模数，变换域密钥及数据还须遵循表的根与排列约定。相同 q/N 不证明表示或实际秘密身份相同。显式模数下的系数须保持规范范围；密钥导入及加密契约见 [primus_glwe](../primus_glwe/README.zh_CN.md)。

分解式 MVB 要求奇数系数模数，准备后的整数因子保留 NTT 表示；因子范数会放大 BR 噪声。

Sparse BR 须在 `config.method` 中显式选择 `BlindRotationMethod::Sparse`；仅使用固定重量秘密仍可运行 classic BR。Sparse 要求 binary 重量 `0<h<n`、`copy_count>=1`、`bucket_count>=max(copy_count,h)`。两种顺序均支持 PBS、ManyLUT、MVB 和 CBS。PBS 配置可用，不代表 CBS 输出精度或 CMux 噪声余量充分。

对于共享 sparse 密钥和 LUT 的独立 u32 或 u64 输入，`sparse::SparseGlweBlindRotationBatchWorkspace::new(key)` 预分配四份互不重叠的工作区。`blind_rotate_lookup_table_many_to` 无分配地写入调用方提供的配对 coefficient GLWE 输出切片，在单线程中按四输入交错处理，剩余输入依次按两输入、一输入处理；单输入保留普通内核。输入顺序与各条密文结果保持不变；调用方可自行选择将环输出相加或分别返回。此原始操作不包含 KS/提取。单输入应用仍使用 `SparseGlweBlindRotationWorkspace`。

重复请求保留 context、密钥和已编译程序，`_to` 方法复用 evaluator scratch 及调用方输出；并发请求需要独立的可变 evaluator。MVB 程序保持与其 context 绑定。`KeyGenerator::try_generate_blind_rotation_key(client, rng)` 根据 context 的 `config.method` 仅生成 BR 材料；独立组件须使用相同的实际秘密和变换表示。独立材料组合及逐调用借用契约见 [KeyGenerator](src/key.rs)、[Evaluator](src/evaluator.rs) 和 [CircuitBootstrapEvaluator](src/circuit_bootstrap/evaluator.rs)，默认流程无需手工组合资源。借用资源执行 CBS 时，先编译程序，再通过 `CircuitBootstrapEvaluator::try_new` 绑定所选 gadget 参数与 circuit key。

OMR 等只消费 BR 的组合流程可以通过 `BlindRotationKey::try_generate`，从输入秘密及目标 GGSW 参数直接建钥，无需准备 PBS 返回域；见[建钥契约](src/key.rs)。

## Features

默认 features 为空，普通依赖已启用 `ntt`，无需后端开关，单独使用不引入 Fourier/FFT。可选 `simd` 启用依赖中的 nightly SIMD 算术。内置 NTT 表另有自身的[运行时 SIMD 分派](../primus_ntt/README.zh_CN.md#simd-backend-与编译目标)。

## 基准

```sh
cargo bench -p primus_tfhe_glwe_ntt --bench pbs
```

| Target | 计时请求 |
| --- | --- |
| [pbs](benches/pbs.rs) | 一次完整 PBS；dense u32/u64、fixed-weight classic/sparse u64；显式 Low/High 比较组见[测试指南](../../guides/development/testing.md#tfhe-benchmarks) |
| [modulus_domains](benches/modulus_domains.rs) | q=Q/q1024 的两种顺序完整 PBS；用 `PRIMUS_DOMAIN_CASE=same/bk`、`split/bk`、`same/kb` 或 `split/kb` 选择 |
| [many_lut](benches/many_lut.rs) | 一次双输出 grade/flag ManyLUT，u64 |
| [mvb](benches/mvb.rs) | 一次 17 输出阈值 MVB，u64 |
| [cbs](benches/cbs.rs) | 一次谓词 CBS、CMux 和单系数 LWE 返回，u64 |
| [cbs_identity](benches/cbs_identity.rs) | bit 0/1 的 identity CBS → NTT GGSW 或 CBS＋CMux；派生 G1 Q54，padded/MSB 输入 |

每次迭代使用已准备的密钥、LUT 和缓冲测量一个服务端请求，准备和工作流解密校验不计时。ManyLUT/CBS 基准不包含示例后续的密文算术。只有 fixed-weight classic/sparse PBS 配对仅改变 BR 算法，dense 用例使用不同参数。计时范围与比较限制见[基准指南](../../guides/development/testing.md#tfhe-benchmarks)。

`cbs_identity` 使用仅在 bench 中定义的派生比较配置，不是教学预设或作者协议的原样复现。测量前检查 bit 0/1 的真实深度 1 CMux 消费，失败直接报错。这些有限 fixture 不证明安全性、失败率或更深树的精度；见[参数映射和验证范围](../../guides/performance/bootstrap-functional-comparison.md#glwe外部cbs功能参考)。

OMR 的两阶段 clue 检测及 `classic_two_stage` / `sparse_two_stage` 基准位于独立的 [primus_omr](../../../primus_omr/README.zh_CN.md) 仓库，请在该仓库根目录运行。

## 进一步阅读

[API 源码](src/lib.rs) · [共享编码与错误](../primus_tfhe/README.zh_CN.md) · [数值契约](../../guides/development/bootstrapping-contracts.md) · [性能说明](../../guides/performance/README.zh_CN.md)
