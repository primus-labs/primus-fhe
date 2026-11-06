# 测试、示例与基准运行

本指南区分编译检查、普通测试、doctest、示例执行和性能测量。运行入口以 [justfile](../../justfile) 为准，包、target 与所需 features 以各 crate 的 `Cargo.toml` 为准。库的选择和组合见[开发导航](README.zh_CN.md)。

## 常用验证入口

需要 Rust、Clippy、rustfmt、`cargo-nextest` 和 `just`。普通命令使用当前工具链；SIMD 命令使用 nightly。

| 入口 | 范围 |
| --- | --- |
| `just fmt-check` / `just fmt` | 检查格式 / 写入格式化结果 |
| `just check [package] [features]` | all-targets 编译，包括所选 features 允许的示例和基准 |
| `just lint [package] [features]` | all-targets Clippy，警告视为错误 |
| `just test [package] [features]` | nextest 普通测试，显式使用 `--lib --tests` |
| `just test-doc [package]` | doctest，与 nextest 分开执行 |
| `just simd [package]` | nightly、all-features 的 Clippy 与普通测试 |
| `just schemes` | BFV/BGV 与共享编码的 batching 编译/lint/普通测试，并执行普通系数/槽、高级子环示例及独立普通依赖消费者 |
| `just parallel` | stable 的可选 limb 并行：NTT、lattice、BFV/BGV 的 all-targets lint 和普通测试，选择 `rns,batching,parallel`，每个测试进程的Rayon pool为4线程 |
| `just tfhe` / `just tfhe-simd` | 所有 `primus_tfhe*` 包的 Clippy 与普通测试；前者选择 NTT 和双 FFT，后者使用 nightly、all-features |
| `just` | 格式检查、workspace Clippy 与普通测试，选择 `ntt,fourier,rustfft,tfhe-fft` |
| `just ci` | 在 `just` 之上执行 doctest、BFV/BGV batching 流程、stable parallel、可选依赖隔离编译和 Barrett derive 回归 |
| `just ci-nightly` | workspace 全 features 的 Clippy、普通测试、doctest、严格 private rustdoc 和 SIMD-only 编译 |

上表可选的 `package` 默认为 `*`，也接受包名或加引号的 Cargo glob。单独调用 `check`、`lint`、`test` 时，`features` 默认空字符串，即只使用各包的默认 features；它们不会自动选择 `just` 的 NTT/双 FFT 组合。例如：

```sh
just test primus_lattice ntt,rustfft,tfhe-fft
just test-doc primus_lattice
just tfhe
```

all-targets 只编译或 lint 示例与基准，不执行它们。nextest 不执行 doctest；`test-doc` recipe 使用默认 features，需选其他 features 时直接调用 `cargo test -p <package> --doc --features <features>`。普通测试保持 `--lib --tests`，避免混入 Criterion target。

[开发 profile](../../Cargo.toml) 设置 `opt-level=1`，test profile 继承它；release/bench 使用默认配置。需要验证 release 下的检查或数值行为时，对相关普通测试另加 `--release`。[GitHub CI](../../.github/workflows/ci.yml) 分 stable/nightly 两个 job；示例执行和性能采样按需进行，不加入普通 CI 的大参数运行。

## Features 与独立消费者

| 包或能力 | 默认与选择方式 |
| --- | --- |
| `primus_fft` | 默认不启用 FFT 引擎；用 `rustfft`、`tfhe-fft` 或两者 |
| `primus_lattice`、`primus_glwe`、`primus_ntru` | 按需选择 `ntt`、`rustfft`、`tfhe-fft`；FFT 引擎 feature 同时启用 Fourier 能力 |
| 两个 TFHE Fourier 后端 | 默认 RustFFT；加 `--features tfhe-fft` 启用双引擎；用 `--no-default-features --features tfhe-fft` 单选 TFHE-FFT |
| `primus_encoding`、`primus_bfv`、`primus_bgv` | 默认无 batching；显式选 `batching` 启用共享槽编码，BGV 系数工作流无需 `encoding/rns`；BFV 正常依赖显式启用 `encoding/rns` |
| GLWE Split35 trace | 低层 `primus_glwe` 需显式添加 `split-trace`；GLWE Fourier 后端默认启用此能力，ordinary 仍是默认表示。关闭后端默认 features 后按需添加 `split-trace`；GLWE Fourier 本身包含系数建钥用的内部辅助 NTT/CRT 依赖，不启用 NTT GLWE API |

稳定工具链上的其他可选功能包括 `primus_data/aligned-vec`、integer/lattice 的 `serde`、`primus_modulus/derive`、`primus_distr/high_precision` 及 lattice/encoding 的 `rns`。独立包验证须显式选择需要的功能，不能依赖其他 workspace 消费者合并 features。

`primus_ntt/parallel`显式启用有界limb调度，经lattice、raw RNS GLWE与BFV/BGV转发，
默认关闭。`just parallel`在stable上独立验证，不能用nightly的all-features结果代替。
N4096的prefix测试比较T1/T2/T4正逆变换、坏geometry写前拒绝，以及pool准备后的
跨线程零分配；任务借用互不重叠的limbs，不各自复制整套密码scratch。该测试不是完整算法的并行性能保证，
总线程仍须由`RAYON_NUM_THREADS`或调用方既有pool约束。

`just ci` 对 `primus_modulus --features derive` 做 all-targets 编译，并单独运行
`derives` 测试目标；不启用 Cargo `simd`，与 nightly 的 portable-SIMD 派生路径分开覆盖。
该过滤不会重跑 modulus 的其他数值测试。只复现这项回归时使用：

```sh
cargo nextest run -p primus_modulus --lib --tests --features derive -E 'binary(derives)'
```

workspace 的普通 `just` 已因 raw `primus_glwe_rns` 的依赖启用 `primus_lattice/rns`，
并因 `primus_bfv` 的依赖启用 `primus_encoding/rns`，包含相关条件测试；单独选择这两个包时仍需显式启用 `rns`。BFV/BGV 系数工作流与无 codec 的 raw GLWE 分别在所属 crate 验证，不能以 workspace feature 合并替代各自的独立依赖检查。BGV 的 phase 为 `c0+c1*s=m+p*e`，使用精确 centered CRT 恢复；共享 batching 不包含 BFV 解码器。`just schemes` 额外选择 `rns,batching`，覆盖 BFV/BGV 槽例及小明文子环嵌入。只准备明文 n 不会改变实际密文/秘密的 N。

```sh
cargo nextest run -p primus_fft --lib --tests --features rustfft,tfhe-fft
cargo check -p primus_tfhe_ntru_fourier --lib --no-default-features --features tfhe-fft
cargo nextest run -p primus_glwe -p primus_tfhe_glwe_fourier --lib --tests --no-default-features --features tfhe-fft,split-trace
```

Cargo 会跳过缺少 `required-features` 的 target，测试内部也可能按 feature 条件编译。`--all-targets` 不等于启用全部 features；空运行不能记为数值验证。需要查看当前选择的普通测试时使用 `cargo nextest list -p <package> --lib --tests --features <features>`，该命令可能先编译测试。

依赖或 feature 边界变化时，可在 workspace 外的临时 Cargo 包复用一个相关 example，只声明它直接使用的普通依赖与选定后端。用独立 `[workspace]` 隔离，并通过 `cargo tree -e normal,features` 核对依赖、执行示例验证结果；不要带入 dev-dependencies。`--lib --no-default-features` 编译与独立消费者验证分别检查库自身和实际组合。

SIMD feature 使用 nightly；`primus_ntt` 的 x86 intrinsic 分派另外受 CPU 能力控制，不要求 Cargo `simd`。NTT 私有差分测试会逐一选择硬件支持的后端，避免自动分派遮住 AVX2 等路径。Fourier 复数 FMA 使用编译时 `avx512f` 条件，既有舍入测试覆盖向量块和标量尾部；未启用该条件时，完整长度走标量循环。未满足硬件或编译条件的分支不能计为已执行，本机通过不代表其他 CPU 或架构也验证过。

## 测试与示例的职责

普通测试使用能保护目标契约的小参数，保留字宽、模数/舍入边界、必要的 SIMD 块与尾部，以及不同变换的数值差异。优先固定 seed 和独立 oracle；不通过挑选成功 seed 或放宽阈值掩盖失败。基础契约在所属 crate 验证，TFHE 测试验证公开接口的端到端组合，避免重复底层覆盖。

示例用代表性参数展示推荐工作流，基准测量指定负载；两者的尺寸不自动成为普通测试要求。TFHE 示例使用 u64，从后端 `experimental` 配置开始。这些配置的适用操作和证据限制见[参数目录](tfhe-parameters.md)，不据有限样本解密成功推断安全性或失败概率。

例如，运行普通 PBS：

```sh
cargo run --release -p primus_tfhe_glwe_ntt --example ntt_basic
```

其他操作的示例见各后端 README。当前 Fourier 示例明确使用 RustFFT，需要 `rustfft` feature；切换 bench/test 的 FFT 引擎不会自动改写示例中的引擎类型。

## BFV/BGV 工作流与基准

在本仓库根目录运行：

```sh
just schemes
cargo run -p primus_bgv --example coefficients
cargo run -p primus_bgv --example slots --features batching
cargo run -p primus_bfv --example coefficients
cargo run -p primus_bfv --example slots --features batching
cargo run -p primus_bgv --example ciphertext_multiplication -- --hybrid
cargo run -p primus_bfv --example ciphertext_multiplication -- --hybrid
cargo run -p primus_bgv --example leveled_coefficients
cargo run -p primus_bgv --example leveled_slots --features batching
cargo run -p primus_bfv --example leveled_coefficients
cargo run -p primus_bfv --example leveled_slots --features batching
cargo check -p primus_bfv --lib --no-default-features
cargo check -p primus_bgv --lib --no-default-features
cargo check -p primus_encoding --lib --no-default-features --features batching
just bench-smoke primus_bgv leveled --features batching
just bench-smoke primus_bfv multiplication --features batching
python3 scripts/check_scheme_consumers.py
```

BGV `workflow` 的一次迭代包含 encode/embed、真实公钥加密、plain-add、dense
plain-mul、精确恢复和 extract/decode，预分配与建钥在计时外。它测完整单次 packed
请求，不能与仅测 evaluator 的结果直接比较。`leveled` 另外测两次 fresh public
加密、ct×ct/square/relin、密文旋转、Alice→Bob 换钥、两次 p-corrected prime drop
和 slot 恢复的完整请求。模数 level 与 gadget digits 是两种参数，各层 key 独立生成；
`row_rotation_key` / `row_swap_key` 复用编码器的槽布局，生成由
`BgvAutomorphism` 执行的真实密文操作。求值操作从 key 推导 level；没有绑定
key 的操作仍显式选择 level。推导见
[BGV 求值契约](bgv-evaluation.md)。参数、布局和当前接口见
[BGV](../../crates/primus_bgv/README.zh_CN.md)、[BFV](../../crates/primus_bfv/README.zh_CN.md)
及[共享编码](../../crates/primus_encoding/README.zh_CN.md)。

BFV `multiplication` 消费普通 `BfvMultiplication` 预备入口，测量包含 encode/embed、
两次 fresh 公钥加密、mul/square/relin、行旋转、跨 client 换钥、两次 BFV rounded
drop 和恢复/decode 的完整请求。为可比历史完整请求，它显式指定相同的 computation-only
P；普通示例由入口自动准备 P。计时不包含 context、auxiliary P、keys 与 scratch 准备；
`-- --test` 只是正确性 smoke，不能替代统计采样。RNS NTT 路径精确保留 integer
tensor，P>NQ 在构造时检查。独立 integer schoolbook 及 raw/scaled/key-column 检查
留在私有数学测试，默认 API 不为 test/bench 暴露内部表示，数学独立性不依赖可见性。
完整代数与固定 Delta 误差见 [BFV 求值契约](bfv-evaluation.md)。普通测试核对任意宽
schoolbook/CRT/direct DFT、key phase、截断 residual 和 prepared 零分配；不得
把成功的解密往返当作整数取整或噪声证明。

基础 `coefficients`、`slots` 只展示公钥加密、明文加/乘与恢复，两次请求复用 setup 和
求值输出，不需要 evaluation key 或 backend 选项。Slots 使用 n=N，由 context 推导
编码器的 N/p，`encode_to` 直接写 plaintext；加密/恢复使用分配式便利入口。
`ciphertext_multiplication` 单独引入 relin 与 Radix/Hybrid；高级例和 allocation 测试
验证 `_to` 的复用契约。
显式 borrowed-secret/workspace、n<N 子环及跨 client 多级链留在高级例。
`just schemes` 还运行 `scripts/check_scheme_consumers.py`：在临时 workspace 中，
只用 examples 实际所需的普通依赖执行四个基础流程、两方案的密文乘法双后端和 BFV
working-basis 双后端，另用一个BGV三层系数流程覆盖drop、自同构与换钥，共8个独立包。
这避免 dev-dependencies 或 workspace feature 合并掩盖接口问题，不展开完整参数矩阵。
系数消费者不启用 batching；槽消费者只需
启用方案的 batching feature，由该方案传递到共享编码器。脚本不是公开验证 API。

## BFV临时工作基

`working_evaluation_keys`用独立整数CRT/nearest-round/scaled-embed oracle检查全部prefix、
Radix/Hybrid及selected-component relin/switch/auto。`leveled_multiplication`核对真实
multiply/square/alias与恢复外部Q；`leveled_parameters`检查有限family/depth准入与实际
ordinary client/key绑定。分配检查复用allocation test的既有harness。

```sh
cargo test -p primus_bfv --test working_evaluation_keys --test leveled_multiplication --test leveled_parameters
cargo run -p primus_bfv --example working_basis
cargo bench -p primus_bfv --bench working_basis -- --test
```

普通行为主要用小环；工厂绑定与示例需要一份实际N16384 family。外部consumer额外复制
该例子，以正常依赖验证两keybackend。BFV的dashu-int现用于精确冷参数认证，是正常
运行依赖；BGV仍独立，不依赖BFV planner。Criterion不进入任何normal tree。

## Context/level 与 raw 边界

普通密文由context分配，clone和借用view保留本地context/level；自动恢复从密文取level。
同形不同context、错level、错误输出在写入/RNG前拒绝。`from_raw` / `zero_raw`及显式
level恢复仍有独立caller合同，`try_bind_ciphertext`对已知来源的raw数组执行一次完整
长度/canonical检查，不证明真实secret或外部NTT来源。普通role key的prepare也检查
同一context，但同context不同actual secret仍由调用方匹配，详见
[方案绑定与互操作](scheme-context-binding.md)。

工作基不是永久modulus drop。普通参数证书不涵盖collective/raw/mixed输入，增加其他
运算后须重计噪声，见[完整契约](bfv-working-basis.md)。

## TFHE benchmarks

四后端的基准位于各自 `benches/`，每个文件就地组织参数和准备工作。选择一个包与操作：

```sh
just bench primus_tfhe_glwe_ntt pbs
just bench-smoke primus_tfhe_ntru_fourier one_hot
```

`just bench <package> <target> [Cargo options…]` 执行 Criterion 测量；`bench-smoke` 追加 `-- --test`，执行构造、请求和校验，不做统计采样。Smoke 仍有密钥生成和大参数运算成本，不能把它的耗时当作求值延迟。

一次测量四后端的普通 u64 PBS（Fourier 使用默认 RustFFT）：

```sh
cargo bench -p 'primus_tfhe_*_ntt' -p 'primus_tfhe_*_fourier' --bench pbs -- 'classic_dense/u64$'
```

| target | 一次迭代的负载 |
| --- | --- |
| `pbs` | 一次完整 LWE→LWE PBS；提供 dense classic u32/u64 与 fixed-weight classic/sparse u64 |
| `many_lut` | 一次盲旋转及多项 LWE 返回 |
| `mvb` | 一次完整 factorized MVB，返回多项阈值结果 |
| `cbs` | 自定义谓词的 CBS → 实际 CMux → 单系数 LWE 返回（`predicate_cmux_return`） |
| `cbs_identity`（GLWE） | G1 NTT、G2 Fourier CMUX2/CMUX3 派生参数，bit 0/1；分别测 CBS→GSW 和 CBS＋CMux，显式选择 padded/MSB |
| `one_hot`（仅 NTRU） | 生成非零 NGSW selectors，再执行多路 CMux |

Fourier 引擎按前面的 feature 规则选择；GLWE `cbs_identity` 仅在 `split-trace` 启用时注册 Split35 用例；关闭默认 feature 后若不选引擎，Fourier bench 会报错。具体函数、消息空间和参数见[当前基准配置](tfhe-parameters.md#current-backend-benchmarks)及各文件。固定重量 classic/sparse 在同一后端使用相同参数，仅更换算法；dense classic 属于另一参数组，不能把两组时间差解释成算法加速。跨后端的噪声、分解和返回路径也不同。

密钥生成、公开程序编译、加密、工作区/输出分配和解密校验均在计时之外。每次迭代处理一个完整请求，throughput 不按输出数放大；单条基准测固定输入的延迟；批量吞吐中的每条平均成本不能当作尾延迟。Criterion 过滤器只控制采样，**不会跳过 `bench_function` 外的准备和校验**。

比较时固定 CPU、工具链、features、参数和完整负载，不混用不同核型的结果。构建、smoke 和正式采样分别记录；Criterion 提供统计输出，历史测量及其适用范围见[性能指南](../performance/README.zh_CN.md)。

GLWE `cbs_identity` 分开测量 CBS→变换域 GGSW 和 CBS＋一次真实 CMux；输入编码
可选 padded/MSB。Fourier ordinary/Split35 只改变 trace 表示，BR、SS 和输入 KS 不变。
用环境变量限制实际准备的组；详细取值和参数由 [NTT](../../crates/primus_tfhe_glwe_ntt/benches/cbs_identity.rs)
及 [Fourier](../../crates/primus_tfhe_glwe_fourier/benches/cbs_identity.rs) 文件就地说明：

```sh
just bench-smoke primus_tfhe_glwe_ntt cbs_identity
PRIMUS_CBS_ENCODING=msb cargo bench -p primus_tfhe_glwe_fourier --bench cbs_identity --features tfhe-fft
```

固定 fixture 的消费检查不认证安全性、DFR 或任意深度的消费精度。TFHE-FFT 在构造
时自动规划，跨进程的浮点舍入与耗时可能不同；历史结果不能替代当前校验。

### GLWE modulus-domain comparison

`modulus_domains` 显式选择 q=Q 或 q1024（`same`/`split`），以及 BR→KS 或
KS→BR（`bk`/`kb`）；转换计入完整请求。未设置或无效选择直接报错。Fourier 此
目标只使用 TFHE-FFT。`cbs_identity` 另有 `PRIMUS_CBS_DOMAIN=same|split` 的
NTT 比较组；配置与校验范围在 bench 文件中维护。

```sh
PRIMUS_DOMAIN_CASE=split/bk cargo bench -p primus_tfhe_glwe_ntt --bench modulus_domains
PRIMUS_DOMAIN_CASE=same/kb cargo bench -p primus_tfhe_glwe_fourier --bench modulus_domains --no-default-features --features tfhe-fft
```

这些是独立比较配置，不扩大默认 `pbs` 组，也不证明任意两域 CBS 参数可用。

### GLWE functional comparison benchmarks

两个 GLWE `pbs` target 另有显式 Low/High 功能比较组，配置与完整消费检查在对应
bench 内；参数不同，不与默认 dense/fixed-weight 组混排。例如：

```sh
PRIMUS_PBS_CASE=ntt-q50-derived/low cargo bench -p primus_tfhe_glwe_ntt --bench pbs
PRIMUS_PBS_CASE=tfhe-fft/high cargo bench -p primus_tfhe_glwe_fourier --bench pbs --features tfhe-fft
```

算法、参数、完整计时边界和外部适配器的差异见[跨方案比较](../performance/bootstrap-functional-comparison.md)。

## 独立应用仓库

OMR 和高精度查表不属于本 workspace。它们通过 path 依赖使用同级 `primus-fhe`；
在各自根目录执行验证和基准命令，core 的 `just` 不包含它们。

- [OMR 验证与完整检索基准](../../../primus_omr/README.zh_CN.md#验证)：two-stage 检测、board 吞吐、encode/digest/recovery。
- [高精度查表验证与基准](../../../primus_high_prec_lut/guides/development/testing.md)：后端 features、公开表创建、完整求值、one-hot 与 primitive 计时边界。
