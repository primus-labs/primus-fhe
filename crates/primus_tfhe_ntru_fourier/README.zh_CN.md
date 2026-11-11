# primus_tfhe_ntru_fourier

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

基于原生环面和 Fourier 变换的 NTRU TFHE 后端，提供 PBS、ManyLUT、分解式 MVB、Boolean 门、CBS 和 one-hot，支持 classic binary/ternary、sparse fixed-weight binary 或直接 block binary 盲旋转（Block 要求 u64）。外部 LWE 与环秘密独立，见[操作指南](../primus_tfhe/README.zh_CN.md#选择同态操作)和 [NTRU 参数/密钥域](../primus_tfhe_ntru/README.zh_CN.md)。

## 快速开始

```sh
cargo run -p primus_tfhe_ntru_fourier --release --example ntru_fourier_basic
```

[basic 示例](examples/ntru_fourier_basic.rs)将加密输入组合成 `z=2*x+y`，计算 `score=min(z,6)`，再执行第二次 PBS 得到 `price=2*score+[score>=4]`。它使用 u64、输入输出消息模数 t=32，外部 q=2^24 与环 Q 不同。密钥、LUT、evaluator 和缓冲重复使用；源码标明客户端/服务端阶段，只解密最终结果。反馈须满足编码兼容、合法 padded 输入和足够噪声余量。

## 实验配套参数

```rust
use primus_tfhe_ntru_fourier::{experimental, TfheContext};
use primus_fft::RustFftTable as Table;

let config = experimental::CLASSIC_PBS_U64;
// Context 使用 config.messages；构造前修改 output_modulus 即可覆盖默认输出域。
let context = TfheContext::<u64, Table, _>::try_from_pbs_config(config)?;
```

从 [experimental](src/experimental.rs) 选择操作配置。`PbsConfig` 包含外部 q、环 Q、BR/返回 KS 及消息；`CbsConfig` 添加 CBS gadget，使用 `TfheContext::try_from_cbs_config`。这些算术教学参数的**安全性及失败概率尚未评估**，参数和噪声角色见[家族指南](../primus_tfhe_ntru/README.zh_CN.md#实验配套参数)。

`PbsMessageConfig::new(t_in)` 默认输入输出消息模数相同，`.with_output_modulus(t_out)` 可独立修改输出。创建 PBS context 前设置 `config.messages`，CBS 则设置 `config.pbs.messages`；客户端和编译器派生相应 codec。同钥消息覆盖见[选择输出编码](../primus_tfhe/README.zh_CN.md#选择输出编码)。

## 操作示例

示例均使用 u64，在请求循环外准备可复用状态。替换快速开始命令中的示例名即可运行其他本库流程。

| 流程 | `experimental` 配置 | 完整示例 |
| --- | --- | --- |
| 两次连续 PBS | `CLASSIC_PBS_U64` | [ntru_fourier_basic](examples/ntru_fourier_basic.rs) |
| `admin OR (member AND NOT revoked)` | `CLASSIC_PBS_U64`，消息 4→4 | [ntru_fourier_boolean](examples/ntru_fourier_boolean.rs) |
| 使用 sparse BR 的相同评分流程 | `SPARSE_PBS_U64` | [ntru_fourier_sparse](examples/ntru_fourier_sparse.rs) |
| ManyLUT grade/flag，再做密文组合 | `CLASSIC_MANY_LUT_U64` | [ntru_fourier_many_lut](examples/ntru_fourier_many_lut.rs) |
| CBS 谓词 → CMux → 环加法 → LWE | `CLASSIC_CBS_U64` | [ntru_fourier_circuit_bootstrap](examples/ntru_fourier_circuit_bootstrap.rs) |
| 同一输入产生 17 个数值阈值标志 | `CLASSIC_THRESHOLD_MVB_U64` | [ntru_fourier_mvb_thresholds](examples/ntru_fourier_mvb_thresholds.rs) |
| Split one-hot CBS → 四路记录选择 | `CLASSIC_ONE_HOT_U64` + split40 / `PairedTrace` | [ntru_fourier_one_hot](examples/ntru_fourier_one_hot.rs) |

普通 PBS/ManyLUT 和 MVB 使用 `context.try_generate_keys(rng)`。将 `client.external_lwe_secret_key()` 绑定到 `context.encryptor`；Rounded PBS/ManyLUT 输出用 `pbs_decryptor`，Scaled MVB 输出用 `mvb_decryptor`。公钥输入使用 `public_encryptor`，客户端不接收 LUT 或手工 codec。

ManyLUT 通过 `pbs_lookup_table_compiler` / `compile_interleaved_fn` 编译，使用 `context.evaluator`。示例从 t_in=16 映射到 t_out=8，再组合加密 grade/flag 输出；它们不能直接反馈给编码不同的输入 PBS。MVB 使用 `compile_mvb_fn` 和 `mvb_evaluator` 计算同一输入的多个函数，其 Scaled 标志不是 Boolean 门密文。

## 参数与表示

`TfheContext<T, Table, LM>` 用 LM 表示外部 LWE q 的模数类型，`config.ring_modulus` 指定环 Q，两者共用系数字宽 T。外部维数 n 独立于环长度 N。`context.allocate_lwe_ciphertext()` 分配外部 LWE 存储，`allocate_accumulator_ciphertext()` 分配系数域 NTRU 存储；分配本身不做加密。

PBS 在 Q 下使用环秘密 f 求值，然后逐系数 Q→q 最近舍入、提取，再于 q 下 LWE KS 到外部秘密 s。ManyLUT 的多输出共享一次 Q→q 转换，MVB 则转换各因子乘积。返回缩放已有相位，不重新生成 q 编码中心；MVB 须预算 `(q/Q)*round(Q/t_out)` 与 `round(q/t_out)` 的差及返回噪声。独立环结果的返回使用[家族返回 API](../primus_tfhe_ntru/README.zh_CN.md#ntrulwe-返回)。

环 Q 只支持 `NativeModulus<T>`，不支持 `PowOf2Modulus` 环，但外部 LWE q 可独立使用 `PowOf2Modulus`。`RustFftTable` 和 `TfheFftTable` 均支持 u32/u64。变换域密钥、数据和 evaluator 须使用**同一个 FFT 表实例**，长度相同不能证明表示一致。

Classic、public lift 和 CBS 在 Fourier 转换前先生成原生模环系数行。Sparse 和 block 以系数形式保存控制行。普通 Classic 与 Sparse 支持 u32/u64。Split 精度和直接 Block BR 要求 u64。使用 `TfheContext::try_from_parameters` 绑定已准备的 PBS 参数并检查字宽。

从旧版未约简复数生成路径迁移时，须重新生成受影响的密文和求值密钥。若曾对外提供相关材料，须更换对应环秘密，以及由受影响 BR 材料保护的外部 LWE 秘密。已有参数的数值误差预算也须重新核对。

CBS reverse trace 在自同构前对 unsigned 系数执行 `floor(c/2)`，不对 Fourier 复数值除二。该取整误差进入相位时会乘环秘密 f；须将它与 trace 映射、FFT 及 KS 误差一起，按最小输出 gadget 尺度预算，非目标系数仍可保留噪声。见 [trace 契约](../primus_ntru/src/trace/fourier.rs)。

MVB 要求实际 Scaled 输出尺度 `round(2^BITS/t_out)` 为偶数；奇数尺度返回 `LookupTableError::OddFactorizationScale`。因子按有符号整数变换，不做环面缩放，须计入 FFT 误差。因子范数同时放大加密初始化与 BR 噪声，返回 KS 噪声在之后加入。MVB 程序保持与其 context 绑定，完整编码及因子误差条件见 [MVB 契约](../primus_tfhe/README.zh_CN.md#固定尺度分解式-mvb)。

只有环秘密 f 需要 NTRU 可逆性及 Fourier 逆稳定性筛选，外部固定重量可为偶数。完整 PBS/CBS 密钥生成还要求 f 的有符号系数幅度小于显式返回 q。形状/basis 检查不证明实际秘密身份或噪声预算，见[家族密钥契约](../primus_tfhe_ntru/README.zh_CN.md#参数与密钥域)。

## 电路自举

创建 CBS context 后，用 `context.try_generate_circuit_bootstrap_keys(rng)` 生成 `(ClientKey, CircuitBootstrapServerKey)`。完整组合包含 BR、返回 KS 及 CBS 材料，`server.server_key()` 也可用于普通 PBS。CBS 和 one-hot 本身输出环/gadget 结果，不执行普通 LWE 返回。

通过 `compile_cbs_fn` / `compile_cbs_slice` 编译 F，再用 `circuit_bootstrap_evaluator_with_lookup_table` 绑定；`circuit_bootstrap_evaluator` 是恒等快捷入口。输入加密使用 `context.encryptor`，输出为 f 下 gadget 尺度 `g_j*F(m) mod Q` 的 `FourierNgswCiphertext`，完整输出 basis 由 circuit key 绑定。CMux 要求整个已编程域上的 F 均为 bit，见 [CBS 契约](../primus_tfhe/README.zh_CN.md#cbs-输出与消费)。

CBS 示例编译 `[m>=2]`，选择加密费用方案，加上加密附加费用，再将一个系数返回为 LWE。`context.accumulator_client(client.accumulator_ntru_secret_key(), t_ring)` 准备 Q 下的 Scaled 候选加解密，无需手工 codec。示例的 t_ring=8 独立于外部消息域及 gadget 缩放。候选须共享 f、Q 和编码，其系数不是独立 SIMD 槽。

重复请求保留 context、密钥组合和 evaluator；`_to` 方法复用 scratch 及调用方输出，并发请求需要独立的可变 evaluator。`KeyGenerator::try_generate_blind_rotation_key(client, rng)` 根据 context 的 `config.method` 仅生成 BR 材料；独立组件须使用相同的实际秘密和变换表示。独立材料及逐调用借用契约见 [KeyGenerator](src/key.rs) 和 [CircuitBootstrapEvaluator](src/circuit_bootstrap/evaluator.rs)。

CBS 示例用 `cbs.into_parts()` 和 `Evaluator::try_from_resources` 转交已有缓冲区，CBS/CMux 执行时借用 `evaluator.bootstrap_resources_mut()`。`return_ring_at_to` 返回指定系数，再用 `context.ring_return_decryptor(secret, t_ring)` 按候选环密文的消息模数解码。返回按 Q→q 舍入和 f→s key switch 执行。纯环工作流仍可保留自带资源的 CBS evaluator，无需返回 scratch。

CBS/one-hot 操作和已编译 MVB 表必须使用原 context 绑定，即使另一个 context 的数值参数相等也不能混用。串行复用时，CBS/one-hot 操作在执行时借用 `BootstrapResources`。通过 `Evaluator::try_from_resources` 恢复普通 PBS 时，传入原 context 和 `server.server_key()`。

## Sparse 盲旋转

在 `config.method`（CBS 的 `config.pbs.method`）中选择 `BlindRotationMethod::Sparse`。它要求 fixed-weight binary 外部秘密，满足 `0<h<n`、`copy_count>=1`、`bucket_count>=max(copy_count,h)`；仅修改秘密分布不会选择 sparse，classic 同样支持固定重量秘密。

PBS、ManyLUT、MVB、CBS 和 one-hot 均支持此模式。Sparse CBS/one-hot 可从 `CLASSIC_ONE_HOT_U64` 开始，其外部秘密为 n800/h32 fixed-weight binary。Dense `CLASSIC_CBS_U64` 不能仅修改算法就改为 sparse：

```rust,ignore
use primus_tfhe_ntru_fourier::BlindRotationMethod;

let mut config = experimental::CLASSIC_ONE_HOT_U64;
config.pbs.method = BlindRotationMethod::Sparse { copy_count: 3, bucket_count: 64 };
let context = TfheContext::<u64, Table, _>::try_from_cbs_config(config)?;
```

随后用 `try_generate_circuit_bootstrap_keys` 生成完整 CBS 组合，使用相同的 CBS/one-hot evaluator 工厂。PBS 配置可用，不代表 CBS 输出精度或 CMux 噪声余量充分。

## Block 盲旋转

设置 `config.method = BlindRotationMethod::Block` 和 `config.external_lwe.secret_key_distr = SecretKeyDistr::BlockBinary { block_size, occupancy }`（CBS 位于 `config.pbs` 内）。使用 u64，逻辑维数须能被正块宽整除，`AtMostOne` 允许空块并增加 dummy，`ExactlyOne` 每块恰有一个 `1` 且无需 dummy。精确 native 生成器直接生成全部 bit 控制与模式要求的独立 dummy 的系数行：首块 NLEV 提升公开 LUT，后续 NGSW 旋转密文。Native 聚合在模 2^64 下精确。Split BR 在每块聚合后拆分并变换，先处理负循环符号和进位，再取高低位。Ordinary 和 split 外积都需要数值误差预算。PBS、ManyLUT、MVB、CBS 和单输入 one-hot 沿用现有工厂与工作区。

通过 `CbsConfig.fourier_precision.blind_rotation` 选择 BR 精度；仅 PBS 的 context 使用 ordinary BR。Trace、SS 精度仍独立选择，可配合已有 split trace/SS 及相应投影策略。只分配选中的聚合频谱，split 转换复用外积 scratch。Context 构造时在准备变换表前拒绝 u32 Block。One-hot 的 `new_pair_workspace` / `with_pair` 支持 Sparse 和 Block（含 split Block BR）；classic 资源不提供 pair 工作区。默认值与预设不变，block 的安全成本与完整 DFR 尚未评估。

## One-hot CBS

[One-hot 示例](examples/ntru_fourier_one_hot.rs)用两位输入选择四个加密记录。`context.one_hot_evaluator(&server)` 使用相同 CBS 组合准备 evaluator，通过 `allocate_nonzero_ngsw_output` 一次分配，只生成 δ₁…δ₃，以 C0 为默认项：

```rust,ignore
one_hot.one_hot_nonzero_ngsw_to(input.as_view(), &mut selectors);
one_hot.cmux_k_to(
    one_hot.nonzero_ngsw_selectors(&selectors),
    candidates[0].as_view(),
    &candidates[1..],
    selected.as_mut_view(),
);
```

`cmux_k_to` 只消费 `1..M` 分支，按顺序与 C1…C(M−1) 配对；全部控制为零时选择 C0，此入口不接收完整 `0..M` 批次。用 `nonzero_ngsw_selectors(...).selector(r)` 按数学编号借用分支，`iter()` 返回 `(r, control)`。完整 selector 和系数域 NLev 输出仍由[家族 one-hot API](../primus_tfhe_ntru/README.zh_CN.md#one-hot-cbs)提供，该处也说明容量和相位保护区。

融合运算通过一次逆变换计算 `C0 + sum_r delta_r*(Cr-C0)`。控制须以已绑定的 basis、秘密和变换表示加密互斥 bit，候选须共享 f、Q 和编码。误差预算应覆盖全部外积误差之和，不能使用顺序 CMux 的估计。Fourier 在求和后舍入，密文系数不保证与逐次 CMux 相同。布局及写入/错误行为见 [one-hot evaluator 契约](src/circuit_bootstrap/one_hot_workflow.rs)。

示例候选使用独立 Scaled t_ring=8，占用环系数而非 SIMD 槽。NLev 输出为 Q 下系数域，公开多项式提升前须用 `write_fourier_form` 转换；NGSW 输出已在 Fourier 表示。其他消费方可使用单控制的 `cmux_to` 和 `external_product_to`。

## Features

默认启用 RustFFT。普通依赖已启用 `fourier`，单独使用不引入 NTT；可选 `simd` 启用依赖中的 nightly SIMD 算术，不选择 FFT 引擎。

| Cargo 参数 | 可用引擎 |
| --- | --- |
| 默认 | RustFFT |
| `--no-default-features --features tfhe-fft` | 仅 TFHE-FFT |
| `--features tfhe-fft` | 两者均可用，由具体表类型选择 |
| `--no-default-features` | 不含具体引擎的泛型 API |

示例导入 `primus_fft::RustFftTable as Table`，并在 [Cargo.toml](Cargo.toml) 声明 `required-features = ["rustfft"]`；只添加 `--features tfhe-fft` 不会切换引擎。仅用 TFHE-FFT 时，将示例导入改为 `primus_fft::TfheFftTable as Table`，对应 target 的 `required-features` 改为 `["tfhe-fft"]`，再使用 `--no-default-features --features tfhe-fft`。基准已经分别实例化每个启用的引擎。

## 基准

```sh
cargo bench -p primus_tfhe_ntru_fourier --bench pbs
```

| Target | 计时请求 |
| --- | --- |
| [pbs](benches/pbs.rs) | 一次完整 PBS；dense u32/u64、fixed-weight classic/sparse u64 |
| [many_lut](benches/many_lut.rs) | 一次双输出 grade/flag ManyLUT，u64 |
| [mvb](benches/mvb.rs) | 一次 17 输出阈值 MVB，u64 |
| [cbs](benches/cbs.rs) | 一次谓词 CBS、CMux 和单系数 LWE 返回，u64 |
| [one_hot](benches/one_hot.rs) | 三个非零 selector 加四路 `cmux_k_to`，u64 |

每次迭代使用已准备的密钥、LUT 和缓冲测量一个服务端请求，准备和解密校验不计时。ManyLUT/CBS 基准不包含示例后续的密文算术。只有 fixed-weight classic/sparse PBS 配对仅改变 BR 算法，dense 用例使用不同参数。见[基准指南](../../guides/development/testing.md#tfhe-benchmarks)。

仅测量 TFHE-FFT：

```sh
cargo bench -p primus_tfhe_ntru_fourier --bench pbs --no-default-features --features tfhe-fft
```

保留默认 features 并添加 `--features tfhe-fft`，可分别测量两个引擎。

## CBS Fourier 精度与投影

`CbsConfig.fourier_precision` 独立选择 BR、trace、scheme switch 精度，默认均为
`Ordinary`；`projection` 默认为 `Separate`。
[one-hot 示例](examples/ntru_fourier_one_hot.rs) 通过一个完整 CBS 配置，显式选择
split 算术和两两融合投影：

```rust,no_run
use primus_tfhe_ntru_fourier::{
    experimental, CbsConfig, FourierCbsPrecision, FourierPrecision, NtruProjectionMethod,
};

let config = CbsConfig {
    fourier_precision: FourierCbsPrecision {
        blind_rotation: FourierPrecision::Split { low_bits: 40 },
        trace: FourierPrecision::Split { low_bits: 40 },
        scheme_switch: FourierPrecision::Split { low_bits: 40 },
    },
    projection: NtruProjectionMethod::PairedTrace,
    ..experimental::CLASSIC_ONE_HOT_U64
};
```

把配置传给 `TfheContext::try_from_cbs_config`，随后使用相同的密钥及 evaluator 工厂，
调用方无需提供 limb 缓冲或 scratch。若只实验 split trace，保留 `Separate`，仅设置
`config.fourier_precision.trace`。

Split 要求 native u64，split BR 支持 classic binary 和 block binary；普通 binary/ternary/sparse BR 及 u64 Block BR
可搭配 split trace 或 SS。`FusedLastStage` 和 `PairedTrace` 均要求 split trace、SS，
两者位宽可以不同。这些策略只融合 NGSW 输出；NLEV/dual 保留独立 trace/SS，精度仍按配置。
SS 输出供 CMux 使用的普通 Fourier 控制。见[支持矩阵及数值限制](../../guides/development/bootstrapping-contracts.md#ntru-cbs-precision-and-projection-support)。

Split40 是实验选项，不代表已认证的错误预算。融合改变舍入及密钥误差传播，首 pair 共享还会
使 one-hot 目标误差相关。PairedTrace 增加密钥存储及 one-hot scratch；为其他负载选用前，
请查看[开销及实测取舍](../../guides/performance/README.zh_CN.md#ntru-projection)。
默认值及预设保持不变。

## 进一步阅读

[API 源码](src/lib.rs) · [共享编码与错误](../primus_tfhe/README.zh_CN.md) · [数值契约](../../guides/development/bootstrapping-contracts.md) · [性能说明](../../guides/performance/README.zh_CN.md)
