# primus_tfhe_ntru_ntt

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

基于显式域模数和 NTT 的 NTRU TFHE 后端，提供 PBS、ManyLUT、分解式 MVB、Boolean 门、CBS 和 one-hot，支持 classic binary/ternary、sparse fixed-weight binary 或直接 block binary 盲旋转。外部 LWE 与环秘密独立，见[操作指南](../primus_tfhe/README.zh_CN.md#选择同态操作)和 [NTRU 参数/密钥域](../primus_tfhe_ntru/README.zh_CN.md)。

## 快速开始

```sh
cargo run -p primus_tfhe_ntru_ntt --release --example ntru_ntt_basic
```

[basic 示例](examples/ntru_ntt_basic.rs)将加密输入组合成 `z=2*x+y`，计算 `score=min(z,6)`，再执行第二次 PBS 得到 `price=2*score+[score>=4]`。它使用 u64、输入输出消息模数 t=32，外部 q=2^24 与环 Q 不同。密钥、LUT、evaluator 和缓冲重复使用；源码标明客户端/服务端阶段，只解密最终结果。反馈须满足编码兼容、合法 padded 输入和足够噪声余量。

## 实验配套参数

```rust
use primus_tfhe_ntru_ntt::{experimental, TfheContext};
use primus_ntt::U64NttTable as Table;

let config = experimental::CLASSIC_PBS_U64;
// Context 使用 config.messages；构造前修改 output_modulus 即可覆盖默认输出域。
let context = TfheContext::<u64, Table, _>::try_from_pbs_config(config)?;
```

从 [experimental](src/experimental.rs) 选择操作配置。`PbsConfig` 包含外部 q、环 Q、BR/返回 KS 及消息；`CbsConfig` 添加 CBS gadget，使用 `TfheContext::try_from_cbs_config`。这些算术教学参数的**安全性及失败概率尚未评估**，参数和噪声角色见[家族指南](../primus_tfhe_ntru/README.zh_CN.md#实验配套参数)。

`PbsMessageConfig::new(t_in)` 默认输入输出消息模数相同，`.with_output_modulus(t_out)` 可独立修改输出。创建 PBS context 前设置 `config.messages`，CBS 则设置 `config.pbs.messages`；客户端和编译器派生相应 codec。同钥消息覆盖见[选择输出编码](../primus_tfhe/README.zh_CN.md#选择输出编码)。

## 操作示例

示例均使用 u64，在请求循环外准备可复用状态。替换快速开始命令中的示例名即可运行其他本库流程，高精度查表示例请在独立的 `primus_high_prec_lut` 仓库根目录运行。

| 流程 | `experimental` 配置 | 完整示例 |
| --- | --- | --- |
| 两次连续 PBS | `CLASSIC_PBS_U64` | [ntru_ntt_basic](examples/ntru_ntt_basic.rs) |
| `admin OR (member AND NOT revoked)` | `CLASSIC_PBS_U64`，消息 4→4 | [ntru_ntt_boolean](examples/ntru_ntt_boolean.rs) |
| 使用 sparse BR 的相同评分流程 | `SPARSE_PBS_U64` | [ntru_ntt_sparse](examples/ntru_ntt_sparse.rs) |
| ManyLUT grade/flag，再做密文组合 | `CLASSIC_MANY_LUT_U64` | [ntru_ntt_many_lut](examples/ntru_ntt_many_lut.rs) |
| CBS 谓词 → CMux → 环加法 → LWE | `CLASSIC_CBS_U64` | [ntru_ntt_circuit_bootstrap](examples/ntru_ntt_circuit_bootstrap.rs) |
| 同一输入产生 17 个数值阈值标志 | `CLASSIC_THRESHOLD_MVB_U64` | [ntru_ntt_mvb_thresholds](examples/ntru_ntt_mvb_thresholds.rs) |
| One-hot CBS → 四路记录选择 | `CLASSIC_ONE_HOT_U64` | [ntru_ntt_one_hot](examples/ntru_ntt_one_hot.rs) |
| 高精度整数查表 | 独立 LUT 仓库的 `NTT_LOW_PREC_C4_O4_DFR128_LOOKUP_U64` | [ntt_lookup](../../../primus_high_prec_lut/examples/ntt_lookup.rs) |

普通 PBS/ManyLUT 和 MVB 使用 `context.try_generate_keys(rng)`。将 `client.external_lwe_secret_key()` 绑定到 `context.encryptor`；Rounded PBS/ManyLUT 输出用 `pbs_decryptor`，Scaled MVB 输出用 `mvb_decryptor`。公钥输入使用 `public_encryptor`，客户端不接收 LUT 或手工 codec。

ManyLUT 通过 `pbs_lookup_table_compiler` / `compile_interleaved_fn` 编译，使用 `context.evaluator`。示例从 t_in=16 映射到 t_out=8，再组合加密 grade/flag 输出；它们不能直接反馈给编码不同的输入 PBS。MVB 使用 `compile_mvb_fn` 和 `mvb_evaluator` 计算同一输入的多个函数，其 Scaled 标志不是 Boolean 门密文。

## 参数与表示

`TfheContext<T, Table, LM>` 用 LM 表示外部 LWE q 的模数类型，`config.ring_modulus` 指定环 Q，两者共用系数字宽 T。外部维数 n 独立于环长度 N。`context.allocate_lwe_ciphertext()` 分配外部 LWE 存储，`allocate_accumulator_ciphertext()` 分配系数域 NTRU 存储；分配本身不做加密。

PBS 在 Q 下使用环秘密 f 求值，然后逐系数 Q→q 最近舍入、提取，再于 q 下 LWE KS 到外部秘密 s。ManyLUT 的多输出共享一次 Q→q 转换，MVB 则转换各因子乘积。返回缩放已有相位，不重新生成 q 编码中心；MVB 须预算 `(q/Q)*round(Q/t_out)` 与 `round(q/t_out)` 的差及返回噪声。独立环结果的返回使用[家族返回 API](../primus_tfhe_ntru/README.zh_CN.md#ntrulwe-返回)。

环 Q 使用 `BarrettModulus<T>`，须存在 NTT 表所需的本原 `2N` 次单位根。自定义表实现 `MonomialNttTable`，内置表支持 u32/u64；须遵守包括 Q 为素数在内的 [NTT 构造约束](../primus_ntt/README.zh_CN.md#构造约束)。Context 构造检查长度和模数，变换域密钥及数据还须遵循表的根和排列约定。相同 Q/N 不证明表示或实际秘密身份相同。

CBS reverse trace 使用 `2^-1 mod Q`，要求奇数 Q 且小于 `2^(T::BITS-1)`。这是模归一化，不是整数舍入除法，也不能将实数噪声独立减半。较晚引入的 KS 误差可留在投影目标系数之外，须按输出 gadget 尺度确定误差界。见 [trace 契约](../primus_ntru/src/trace/ntt.rs)。

仅输出 NGSW 的 CBS 和 one-hot 遵循 `CbsConfig.projection`；实验性 NTT 预设显式使用 `PairedTrace`，两两合并 reverse trace 阶段，将末两层或三层与 scheme switch 融合。NLev 和双输出保留分开路径。各策略的存储与噪声契约见 [`NttNtruProjectionKey`](../primus_ntru/src/scheme_switch/projection.rs)。枚举默认值为 `Separate`；在生成密钥和 evaluator 前选择：

```rust
use primus_ntt::U64NttTable;
use primus_tfhe_ntru_ntt::{experimental, NtruProjectionMethod, TfheContext};

let mut config = experimental::CLASSIC_CBS_U64;
config.projection = NtruProjectionMethod::Separate; // 覆盖性能预设。
let context = TfheContext::<u64, U64NttTable, _>::try_from_cbs_config(config)?;
```

该选择只改变 NGSW-only 输出；结果不必与双输出中的 NGSW 逐位相同。
耗时与存储取舍见[四策略对照](../../guides/performance/ntru-projection-fusion.md#current-strategy-comparison)。预设仍为实验参数，更快的策略不代表更小的噪声预算。

MVB 要求奇数环 Q，准备后的因子保留 NTT 表示。因子范数同时放大加密初始化与 BR 噪声，返回 KS 噪声在之后加入。MVB 程序保持与其 context 绑定，完整编码及因子误差条件见 [MVB 契约](../primus_tfhe/README.zh_CN.md#固定尺度分解式-mvb)。

只有环秘密 f 需要 NTRU 可逆性，外部固定重量可为偶数。完整 PBS/CBS 密钥生成还要求 f 的有符号系数幅度小于显式返回 q。形状/basis 检查不证明实际秘密身份或噪声预算，见[家族密钥契约](../primus_tfhe_ntru/README.zh_CN.md#参数与密钥域)。

## 电路自举

创建 CBS context 后，用 `context.try_generate_circuit_bootstrap_keys(rng)` 生成 `(ClientKey, CircuitBootstrapServerKey)`。完整组合包含 BR、返回 KS 及 CBS 材料，`server.server_key()` 也可用于普通 PBS。CBS 和 one-hot 本身输出环/gadget 结果，不执行普通 LWE 返回。

通过 `compile_cbs_fn` / `compile_cbs_slice` 编译 F，再用 `circuit_bootstrap_evaluator_with_lookup_table` 绑定；`circuit_bootstrap_evaluator` 是恒等快捷入口。输入加密使用 `context.encryptor`，输出为 f 下 gadget 尺度 `g_j*F(m) mod Q` 的 `NttNgswCiphertext`，完整输出 basis 由 circuit key 绑定。CMux 要求整个已编程域上的 F 均为 bit，见 [CBS 契约](../primus_tfhe/README.zh_CN.md#cbs-输出与消费)。

CBS 示例编译 `[m>=2]`，选择加密费用方案，加上加密附加费用，再将一个系数返回为 LWE。`context.accumulator_client(client.accumulator_ntru_secret_key(), t_ring)` 准备 Q 下的 Scaled 候选加解密，无需手工 codec。示例的 t_ring=8 独立于外部消息域及 gadget 缩放。候选须共享 f、Q 和编码，其系数不是独立 SIMD 槽。

重复请求保留 context、密钥组合和 evaluator；`_to` 方法复用 scratch 及调用方输出，并发请求需要独立的可变 evaluator。`KeyGenerator::try_generate_blind_rotation_key(client, rng)` 根据 context 的 `config.method` 仅生成 BR 材料；独立组件须使用相同的实际秘密和变换表示。独立材料及逐调用借用契约见 [KeyGenerator](src/key.rs) 和 [CircuitBootstrapEvaluator](src/circuit_bootstrap/evaluator.rs)。

CBS 示例用 `cbs.into_parts()` 和 `Evaluator::try_from_resources` 转交已有缓冲区，CBS/CMux 执行时借用 `evaluator.bootstrap_resources_mut()`。`return_ring_at_to` 返回指定系数，再用 `context.ring_return_decryptor(secret, t_ring)` 按候选环密文的消息模数解码。返回按 Q→q 舍入和 f→s key switch 执行。纯环工作流仍可保留自带资源的 CBS evaluator，无需返回 scratch。

CBS/one-hot 操作和已编译 MVB 表必须使用原 context 绑定，即使另一个 context 的数值参数相等也不能混用。串行复用时，CBS/one-hot 操作在执行时借用 `BootstrapResources`。通过 `Evaluator::try_from_resources` 恢复普通 PBS 时，传入原 context 和 `server.server_key()`。

## Sparse 盲旋转

在 `config.method`（CBS 的 `config.pbs.method`）中选择 `BlindRotationMethod::Sparse`。它要求 fixed-weight binary 外部秘密，满足 `0<h<n`、`copy_count>=1`、`bucket_count>=max(copy_count,h)`；仅修改秘密分布不会选择 sparse，classic 同样支持固定重量秘密。

PBS、ManyLUT、MVB、CBS 和 one-hot 均支持此模式。Sparse CBS/one-hot 可从 `CLASSIC_ONE_HOT_U64` 开始，其外部秘密为 n800/h32 fixed-weight binary。Dense `CLASSIC_CBS_U64` 不能仅修改算法就改为 sparse：

```rust,ignore
use primus_tfhe_ntru_ntt::BlindRotationMethod;

let mut config = experimental::CLASSIC_ONE_HOT_U64;
config.pbs.method = BlindRotationMethod::Sparse { copy_count: 3, bucket_count: 64 };
let context = TfheContext::<u64, Table, _>::try_from_cbs_config(config)?;
```

随后用 `try_generate_circuit_bootstrap_keys` 生成完整 CBS 组合，使用相同的 CBS/one-hot evaluator 工厂。PBS 配置可用，不代表 CBS 输出精度或 CMux 噪声余量充分。

## Block 盲旋转

设置 `config.method = BlindRotationMethod::Block` 和 `config.external_lwe.secret_key_distr = SecretKeyDistr::BlockBinary { block_size }`（CBS 位于 `config.pbs` 内）。逻辑 LWE 维数须是正块宽的非零整数倍。允许空块，无需 matching 或重复控制。建钥以及 PBS、ManyLUT、MVB、CBS 和 one-hot 沿用相同 context 工厂。每块加密全部 bit 及独立 dummy；首块即使所有指数为零也通过 NLEV 完成提升，后续 NGSW 复用相同外积算术。单输入共享工作区只在构造时分配，不保存占用信息。One-hot 的 `new_pair_workspace` / `with_pair` 共享 Sparse 和 Block 的分组 BR 遍历；classic 资源不提供 pair 工作区，保留单输入调用。预设不变，block 的噪声与安全成本须单独评估。

## One-hot CBS

[One-hot 示例](examples/ntru_ntt_one_hot.rs)用两位输入选择四个加密记录。`context.one_hot_evaluator(&server)` 使用相同 CBS 组合准备 evaluator，通过 `allocate_nonzero_ngsw_output` 一次分配，只生成 δ₁…δ₃，以 C0 为默认项：

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

融合运算通过一次逆变换计算 `C0 + sum_r delta_r*(Cr-C0)`。控制须以已绑定的 basis、秘密和变换表示加密互斥 bit，候选须共享 f、Q 和编码。误差预算应覆盖全部外积误差之和，不能使用顺序 CMux 的估计。布局及写入/错误行为见 [one-hot evaluator 契约](src/circuit_bootstrap/one_hot_workflow.rs)。

示例候选使用独立 Scaled t_ring=8，占用环系数而非 SIMD 槽。NLev 输出为 Q 下系数域，公开多项式提升前须用 `write_ntt_form` 转换；NGSW 输出已在 NTT 表示。其他消费方可使用单控制的 `cmux_to` 和 `external_product_to`。

## 高精度查表

独立仓库中的 [primus_tfhe_ntru_lut](../../../primus_high_prec_lut/README.zh_CN.md) 用于统一位宽、输入输出数量独立的 chunk。其 `NttHighPrecLutContext` 准备整数客户端、完整密钥和求值，调用方无需组合提升或返回工作区。[ntt_lookup 示例](../../../primus_high_prec_lut/examples/ntt_lookup.rs)将 16 位输入映射为 16 位分段费用结果。

LUT 流程组合 one-hot CBS、固定完整选表树、聚合负向旋转和独立 LWE 返回。推荐配置采用 classic BR，显式选择时也支持 sparse；几何、公开表成本及数值限制由 LUT crate 说明。

## Features

默认 features 为空，普通依赖已启用 `ntt`，无需后端开关，单独使用不引入 Fourier/FFT。可选 `simd` 启用依赖中的 nightly SIMD 算术；内置 NTT 表另有自身的[运行时 SIMD 分派](../primus_ntt/README.zh_CN.md#simd-backend-与编译目标)。

## 基准

```sh
cargo bench -p primus_tfhe_ntru_ntt --bench pbs
```

| Target | 计时请求 |
| --- | --- |
| [pbs](benches/pbs.rs) | 一次完整 PBS；dense u32/u64、fixed-weight classic/sparse u64 |
| [many_lut](benches/many_lut.rs) | 一次双输出 grade/flag ManyLUT，u64 |
| [mvb](benches/mvb.rs) | 一次 17 输出阈值 MVB，u64 |
| [cbs](benches/cbs.rs) | 一次谓词 CBS、CMux 和单系数 LWE 返回，u64 |
| [one_hot](benches/one_hot.rs) | 三个非零 selector 加四路 `cmux_k_to`，u64 |

每次迭代使用已准备的密钥、LUT 和缓冲测量一个服务端请求，准备和解密校验不计时。ManyLUT/CBS 基准不包含示例后续的密文算术。只有 fixed-weight classic/sparse PBS 配对仅改变 BR 算法，dense 用例使用不同参数。见[基准指南](../../guides/development/testing.md#tfhe-benchmarks)。

## 进一步阅读

[API 源码](src/lib.rs) · [共享编码与错误](../primus_tfhe/README.zh_CN.md) · [数值契约](../../guides/development/bootstrapping-contracts.md) · [性能说明](../../guides/performance/README.zh_CN.md)
