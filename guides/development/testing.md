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
| `just parallel` | stable 的可选 limb 并行：NTT、lattice、BFV/BGV 的 all-targets lint 和普通测试，选择 `rns,batching,parallel`，测试命令设置 `RAYON_NUM_THREADS=4` |
| `just tfhe` / `just tfhe-simd` | 所有 `primus_tfhe*` 包的 Clippy 与普通测试；前者启用两种 FFT 引擎，后者使用 nightly、all-features |
| `just` | 格式检查、workspace Clippy 与普通测试，选择 `ntt,fourier,rustfft,tfhe-fft` |
| `just ci` | 格式、最小特性和独立消费者编译、Stable Clippy、普通测试和 doctest。主套件启用 batching、Barrett derive 和高精度采样，另跑定向并行、无 batching 分配测试和无变换后端的 NTRU→LWE 返回 |
| `just ci-nightly` | 最小 SIMD 编译、workspace 全 features 的 Clippy 和普通测试、严格 private rustdoc |

上表可选的 `package` 默认为 `*`，也接受包名或加引号的 Cargo glob。单独调用 `check`、`lint`、`test` 时，`features` 默认空字符串，即只使用各包的默认 features；它们不会自动选择 `just` 的 NTT/双 FFT 组合。例如：

```sh
just test primus_lattice ntt,rustfft,tfhe-fft
just test-doc primus_lattice
just tfhe
```

all-targets 只编译或 lint 示例与基准，不执行它们。nextest 不执行 doctest；`test-doc` recipe 使用默认 features，需选其他 features 时直接调用 `cargo test -p <package> --doc --features <features>`。普通测试保持 `--lib --tests`，避免混入 Criterion target。

[开发 profile](../../Cargo.toml) 设置 `opt-level=1`，test profile 继承它；release/bench 使用默认配置。需要验证 release 下的检查或数值行为时，对相关普通测试另加 `--release`。[GitHub CI](../../.github/workflows/ci.yml) 先检查独立特性组合，再 lint 和测试主配置。Stable 的 doctest 与普通测试共用 feature 配置，Nightly 另检查全特性文档的链接与警告。示例和基准由 CI 做编译与 lint 检查，实际执行按需手动触发。

## 开发脚本

从仓库根目录执行。两个脚本的 `--help` 都可用普通 Python 查看。

| 脚本 | 用途与依赖 |
| --- | --- |
| [`check_scheme_consumers.py`](../../scripts/check_scheme_consumers.py) | `just schemes` 调用，验证独立 Cargo 消费者的普通依赖和实际 BFV/BGV 工作流。需要 Python 3.11+ 及已下载的 Cargo 依赖。 |
| [`screen_scheme_parameters.py`](../../scripts/screen_scheme_parameters.py) | 使用 Sage Python 和显式指定的 lattice-estimator checkout 估算公开参数的 bare-LWE 参考成本。命令、示例输入和适用范围见[参数与安全参考](ordinary-parameter-budgets.md#安全输入与离线参考筛查)。 |

## Features 与独立消费者

| 包或能力 | 默认与选择方式 |
| --- | --- |
| `primus_fft` | 默认不启用 FFT 引擎；用 `rustfft`、`tfhe-fft` 或两者 |
| `primus_lattice`、`primus_glwe`、`primus_ntru` | 按需选择 `ntt`、`rustfft`、`tfhe-fft`；FFT 引擎 feature 同时启用 Fourier 能力 |
| 两个 TFHE Fourier 后端 | 默认 RustFFT；加 `--features tfhe-fft` 启用双引擎；用 `--no-default-features --features tfhe-fft` 单选 TFHE-FFT |
| `primus_encoding`、`primus_bfv`、`primus_bgv` | 默认无 batching；显式选 `batching` 启用共享槽编码，BGV 系数工作流无需 `encoding/rns`；BFV 正常依赖显式启用 `encoding/rns` |
| GLWE Split35 trace | 低层 `primus_glwe` 需显式添加 `split-trace`；GLWE Fourier 后端默认启用此能力，ordinary 仍是默认表示。关闭后端默认 features 后按需添加 `split-trace`；GLWE Fourier 本身包含系数建钥用的内部辅助 NTT/CRT 依赖，不启用 NTT GLWE API |

稳定工具链上的其他可选功能包括 `primus_data/aligned-vec`、integer/lattice 的 `serde`、`primus_modulus/derive`、`primus_distr/high_precision` 及 lattice/encoding 的 `rns`。独立包验证须显式选择需要的功能，不能依赖其他 workspace 消费者合并 features。

`primus_ntt/parallel` 默认关闭，由 lattice、raw RNS GLWE 和 BFV/BGV 转发。`just parallel` 运行完整的并行 feature 矩阵。Stable CI 定向执行 `dcrt_prefix` 和 BFV `leveled_parameters`，覆盖并行变换的写入前拒绝、串并行差分和实际进入该路径的求值。线程池配置见 [NTT](../../crates/primus_ntt/README.zh_CN.md#simd-backend-与编译目标)。

`just ci` 在 Stable 主套件中编译并运行 Barrett derive 的普通测试，其中包括 `derives` 目标。
这个组合不启用 Cargo `simd`，与 Nightly 的 portable-SIMD 派生路径分开覆盖。单独复现 `derives` 目标的命令如下。

```sh
cargo nextest run -p primus_modulus --test derives --features derive
```

Workspace 的普通 `just` 会合并其他 crate 的依赖 features。单独选择 lattice 或 encoding 时，按需显式启用 `rns`。`just schemes` 选择 `rns,batching`，并检查 BFV/BGV 的独立普通依赖。

```sh
cargo nextest run -p primus_fft --lib --tests --features rustfft,tfhe-fft
cargo check -p primus_tfhe_ntru_fourier --lib --no-default-features --features tfhe-fft
cargo nextest run -p primus_glwe -p primus_tfhe_glwe_fourier --lib --tests --no-default-features --features tfhe-fft,split-trace
```

Cargo 会跳过缺少 `required-features` 的 target，测试内部也可能按 feature 条件编译。`--all-targets` 不等于启用全部 features；空运行不能记为数值验证。需要查看当前选择的普通测试时使用 `cargo nextest list -p <package> --lib --tests --features <features>`，该命令可能先编译测试。

`gadget_operations`、GLWE 的 `packing_key_switch` 和 NTRU 的 `lwe_key_switch` 按用例选择后端。核对某一引擎时，单独选择对应包和 feature。例如：

```sh
cargo nextest run -p primus_lattice --test gadget_operations --no-default-features --features ntt
cargo nextest run -p primus_glwe --test packing_key_switch --no-default-features --features rustfft
cargo nextest run -p primus_ntru --test lwe_key_switch --no-default-features
```

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

`just schemes` 运行两种方案及共享编码的测试、示例和独立消费者检查。单独运行槽示例或 smoke 时，显式选择 `batching`。

```sh
just schemes
cargo run -p primus_bfv --example slots --features batching
cargo run -p primus_bgv --example leveled_slots --features batching
just bench-smoke primus_bfv multiplication --features batching
just bench-smoke primus_bgv leveled --features batching
```

完整请求的计时边界见 [BFV multiplication](../../crates/primus_bfv/benches/multiplication.rs)、[BGV leveled](../../crates/primus_bgv/benches/leveled.rs) 和 [BGV workflow](../../crates/primus_bgv/benches/workflow.rs)。两方案的示例入口见 [BFV](../../crates/primus_bfv/README.zh_CN.md) 和 [BGV](../../crates/primus_bgv/README.zh_CN.md)。

Stable CI 通过 [独立消费者脚本](../../scripts/check_scheme_consumers.py) 的 `--check-only` 检查普通依赖和 feature 隔离。`just schemes` 还运行消费者示例，覆盖无 batching 的系数路径、带 batching 的槽路径，以及相应的 Radix 和 Hybrid 工作流。

## BFV 临时工作基

```sh
cargo test -p primus_bfv --test working_evaluation_keys --test leveled_multiplication --test leveled_parameters
cargo run -p primus_bfv --example working_basis
just bench-smoke primus_bfv working_basis
```

三个测试目标分别覆盖求值密钥、乘法和参数准入。深度、外部模数基恢复、误差及适用输入范围见 [工作基契约](bfv-working-basis.md)。Context/level 绑定、raw 密文导入与显式 level 恢复见 [方案绑定与互操作](scheme-context-binding.md)。

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
| `pbs` | 一次完整 LWE→LWE PBS；提供 dense Classic u32/u64 |
| `many_lut` | 一次盲旋转及多项 LWE 返回 |
| `mvb` | 一次完整 factorized MVB，返回多项阈值结果 |
| `cbs` | 自定义谓词的 CBS → 实际 CMux → 单系数 LWE 返回（`predicate_cmux_return`） |
| `cbs_identity`（GLWE） | G1 NTT、G2 Fourier CMUX2/CMUX3 派生参数，bit 0/1；分别测 CBS→GSW 和 CBS＋CMux，显式选择 padded/MSB |
| `one_hot`（仅 NTRU） | 生成非零 NGSW selectors，再执行多路 CMux |

Fourier 引擎按前面的 feature 规则选择。GLWE Fourier 的 `cbs_identity` 需要启用 `split-trace` 才注册 Split35 用例。函数、消息空间和当前配置见 [TFHE 参数目录](tfhe-parameters.md#current-backend-benchmarks) 及对应 benchmark 文件。历史结果的适用范围见[性能指南](../performance/README.zh_CN.md)。

Criterion 过滤器只控制采样，`bench_function` 外的准备和校验仍会执行。带独立配置选择的目标可用文件头记录的环境变量限制准备范围。例如 `cbs_identity` 的输入编码和模数域选择见 [NTT](../../crates/primus_tfhe_glwe_ntt/benches/cbs_identity.rs) 与 [Fourier](../../crates/primus_tfhe_glwe_fourier/benches/cbs_identity.rs) 文件。

```sh
just bench-smoke primus_tfhe_glwe_ntt cbs_identity
PRIMUS_CBS_ENCODING=msb cargo bench -p primus_tfhe_glwe_fourier --bench cbs_identity --features tfhe-fft
```

### GLWE modulus-domain comparison

用 `PRIMUS_DOMAIN_CASE` 选择模数域和自举顺序。支持的取值、参数及计时边界见 [NTT](../../crates/primus_tfhe_glwe_ntt/benches/modulus_domains.rs) 与 [Fourier](../../crates/primus_tfhe_glwe_fourier/benches/modulus_domains.rs) 文件。

```sh
PRIMUS_DOMAIN_CASE=split/bk cargo bench -p primus_tfhe_glwe_ntt --bench modulus_domains
PRIMUS_DOMAIN_CASE=same/kb cargo bench -p primus_tfhe_glwe_fourier --bench modulus_domains --no-default-features --features tfhe-fft
```

### GLWE functional comparison benchmarks

普通 `pbs` 默认注册 dense Classic。两个 GLWE 后端还可用 `PRIMUS_PBS_CASE` 单独选择 Low/High 功能对照，具体配置见 [NTT](../../crates/primus_tfhe_glwe_ntt/benches/pbs.rs) 和 [Fourier](../../crates/primus_tfhe_glwe_fourier/benches/pbs.rs) 文件。

```sh
PRIMUS_PBS_CASE=ntt-q50-derived/low cargo bench -p primus_tfhe_glwe_ntt --bench pbs
PRIMUS_PBS_CASE=tfhe-fft/high cargo bench -p primus_tfhe_glwe_fourier --bench pbs --features tfhe-fft
```

算法、参数和完整计时边界见[跨方案比较](../performance/README.zh_CN.md#tfhe-comparisons)。
