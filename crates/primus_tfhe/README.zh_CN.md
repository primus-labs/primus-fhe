# primus_tfhe

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

GLWE 和 NTRU 共用的 LWE 客户端、LUT 编译、编码契约、PBS trait 及 Boolean 门。完整流程从具体后端的示例开始，本指南用于选择操作和消息域。

## 选择同态操作

下文 t 为输入消息模数，N 为环长度，k 为输出数量。普通 PBS 使用 unsigned Rounded 输入，所有 `_to` 操作复用调用方输出及 evaluator 工作区。

| 任务 | 输入域 | 输出与主要 API |
| --- | --- | --- |
| 单变量函数 | 前半区 `0..ceil(t/2)` | 一个 Rounded LWE；`LookupTable` 和 `Evaluator` |
| 奇数全域 | `0..t`，奇数 `t>=3` | 一个 Rounded LWE；奇数全域编译器 |
| ManyLUT | 同一前半区输入；`ceil(t/2)<=N/next_power_of_two(k)` | k 个 Rounded LWE；`InterleavedLookupTable` |
| 分解式 MVB | 同一非空前半区前缀 | k 个 unsigned Scaled LWE；预处理程序和 `FactorizedEvaluator` |
| 有界双输入函数 | 同秘密/编码；`x<B`、`y<R`、`B*R<=ceil(t/2)` | 一个 Rounded LWE；`BivariateLookupTable` |
| Boolean 门 | t=4 下的 Rounded 0/1 | 可串联的 Boolean LWE；`BooleanEvaluator` |
| CBS 后接 CMux | Padded 输入或 GLWE MSB bit；F 在整个域上取 bit 值 | GGSW/NGSW 控制选择加密环候选；`CbsEvaluator` |
| One-hot CBS | 一个 padded chunk，t=2M | NLev/NGSW selectors；[NTRU one-hot](../primus_tfhe_ntru/README.zh_CN.md#one-hot-cbs) |
| 高精度查表 | 多个独立加密、统一位宽的 chunk | 可独立指定输出 chunk 数；独立的 [NTRU LUT 仓库](../../../primus_high_prec_lut/README.zh_CN.md) |

ManyLUT 和 MVB 计算**同一个输入的多个函数**。ManyLUT 用旋转分辨率换取输出数量；MVB 保留步长 1，但因子会放大噪声。Scaled 数值标志、Boolean LWE 和 gadget 控制使用不同编码，不能直接互换。

## Crate 分工与能力

| 家族 | NTT 后端 | Fourier 后端 |
| --- | --- | --- |
| [GLWE 参数与客户端](../primus_tfhe_glwe/README.zh_CN.md) | [GLWE NTT](../primus_tfhe_glwe_ntt/README.zh_CN.md) | [GLWE Fourier](../primus_tfhe_glwe_fourier/README.zh_CN.md) |
| [NTRU 参数与客户端](../primus_tfhe_ntru/README.zh_CN.md) | [NTRU NTT](../primus_tfhe_ntru_ntt/README.zh_CN.md) | [NTRU Fourier](../primus_tfhe_ntru_fourier/README.zh_CN.md) |

| 盲旋转模式 | PBS / ManyLUT | CBS | 分解式 MVB | One-hot / 高精度 LUT |
| --- | --- | --- | --- | --- |
| GLWE classic binary/ternary | 两种 PBS 顺序 | 支持 | 支持 | 未提供 |
| GLWE sparse fixed-weight binary | 两种 PBS 顺序 | 支持 | 支持 | 未提供 |
| GLWE block binary | 两种 PBS 顺序 | 支持 | 支持 | 未提供 |
| NTRU classic binary/ternary | 支持 | 支持 | 支持 | 支持 |
| NTRU sparse fixed-weight binary | 支持 | 支持 | 支持 | 支持 |
| NTRU NTT block binary | 支持 | 支持 | 支持 | One-hot；LUT 接入待完成 |
| NTRU Fourier block binary（u64） | 支持 | 支持 | 支持 | One-hot；LUT 接入待完成 |

四后端均提供私钥及 LWE 公钥客户端。Fourier 支持 RustFFT 和 TFHE-FFT，环模数仅支持 Native。示例配置用于算术教学，未评估安全性及失败概率。NTRU 的外部 LWE 秘密独立于环秘密，只有环秘密需要可逆性和 Fourier 逆稳定性筛选。

## 选择盲旋转算法

四后端均导出 `BlindRotationMethod`，通过 `config.method` 选择；仅改变秘密分布不会切换算法。`Classic` 支持 binary/ternary，包括固定重量分布。显式的 `Sparse { copy_count, bucket_count }` 要求 fixed-weight binary 且 `0<h<n`，不支持 sparse ternary。公开映射重试后匹配仍失败时返回错误，不更改客户端秘密或回退到 classic。

`SecretKeyDistr::BlockBinary { block_size, occupancy }` 独立采样连续块。`BlockOccupancy::AtMostOne` 均匀选择空块或一个位置为 `1` 的状态；`ExactlyOne` 只选择一个位置为 `1` 的状态。逻辑密钥长度须是块宽的非零整数倍。`Classic` 可使用两种分布；`Block` 在四个后端中选择直接按块聚合。全部 bit 控制都参与计算，包括加密的零。仅 `AtMostOne` 增加独立加密的空块 dummy；`ExactlyOne` 不存储或采样它。NTRU Fourier 要求 u64，支持 ordinary 或 split BR；trace、SS 精度保持独立。Block 秘密需要单独评估噪声与安全成本。GLWE ring-KS 保留逻辑 LWE 前缀并补公开零尾，填充后的环长度无需也能被块宽整除。

普通 PBS 先构造 `TfheContext::try_from_pbs_config(config)`，再调用 `context.try_generate_keys(rng)` 得到 `(ClientKey, ServerKey)`。CBS 或 NTRU one-hot 使用 CBS 工厂：

```rust,ignore
let context = TfheContext::try_from_cbs_config(config)?;
let (client, server) = context.try_generate_circuit_bootstrap_keys(rng)?;
let mut cbs = context.circuit_bootstrap_evaluator(&server)?;
```

CBS 组合包含 BR、必需的 KS 及 CBS 材料。`context.evaluator(server.server_key())?` 可用相同密钥绑定普通 PBS。为已有 context 添加 CBS（GLWE 用 `try_with_circuit_bootstrap(gadget, input_encoding, fourier_trace_precision)`，NTRU 用 `try_with_circuit_bootstrap(gadget)`）后，仍须调用 `try_generate_circuit_bootstrap_keys`，不能用普通密钥生成替代。已有客户端可通过 `try_generate_server_key(&client, rng)` 生成普通服务端材料；独立材料生成见后端 `KeyGenerator` 方法。

## 客户端与服务端边界

Client 保留秘密密钥，向 server 提供求值密钥和输入密文。CBS 还接收加密环候选，NTRU 公开多项式提升需要相应的加密材料。Server 编译公开 LUT、求值并返回加密结果，输入输出编码是双方公开约定。各自分配并复用缓冲；示例在同一进程中标明这些阶段。

用 `client.external_lwe_secret_key()` 创建 context 客户端。`context.allocate_lwe_ciphertext()` 分配外部 LWE 存储，`allocate_accumulator_ciphertext()` 分配系数域环存储；两者只分配零缓冲，不做加密。CBS 控制使用 `cbs.allocate_output()`，其布局依赖 gadget basis 和变换表示。

客户端和 evaluator 使用借用视图：`encrypt_padded_to(message, output.as_mut_view(), rng)`、`decrypt(ciphertext.as_view())`、`apply_lookup_table_to(input.as_view(), &lut, output.as_mut_view())`。ManyLUT/MVB 及高精度批次使用预分配的 `LweCiphertext<T>` 切片，每个有效输出需要一个完整 LWE，LUT padding 不增加输出密文数量。

## LUT 与资源生命周期

通过 `context.pbs_lookup_table_compiler()?` 准备可复用编译器，使用 context 配置的输入输出消息域。

| 程序 | 函数输入 | 切片输入 |
| --- | --- | --- |
| 前半区，单输出 | `compile_fn(function)` | `compile_slice(values)` |
| 前半区，多输出 | `compile_interleaved_fn(k, function)` | `compile_interleaved_slice(k, values)` |
| 奇数全域，单输出 | `compile_odd_full_domain_fn(function)` | `compile_odd_full_domain_slice(values)` |

前半区编译为 `D=ceil(t_in/2)` 个输入编程，输出值属于 `0..t_out`。ManyLUT 要求 k 为正且 `D<=N/s`，其中 `s=next_power_of_two(k)`。三个输出占四个槽，但只返回三个密文。回调按输入优先顺序接收 `(input, output_index)`，切片按相同顺序保存 D*k 个值。输出越多，输入噪声余量越小。完整区间及舍入规则见[旋转几何](../../guides/development/bootstrapping-contracts.md#rotation-geometry)。

### 选择输出编码

`PbsMessageConfig::new(t_in)` 默认 `t_out=t_in`，`.with_output_modulus(t_out)` 仅改变输出域；ManyLUT 各 lane 和 MVB 各输出共用该选择。`from_input_bits(4)` 表示 16 个合法 padded 输入、codec 模数 32，默认完整输出模数也为 32，不隐含输出 padding。可失败构造用 `try_from_input_bits`，一般/奇数模数用 `new(t)`。

| Context 工厂 | q 下输入 | Q 下 LUT 输出 | q 下返回输出解码器 |
| --- | --- | --- | --- |
| `pbs_lookup_table_compiler()` | Rounded | Rounded | `pbs_decryptor` |
| `compile_mvb_fn(domain_len, output_count, function)` | Rounded | Scaled | `mvb_decryptor` |

两者共用 `context.encryptor(external_secret)` 或 `public_encryptor(&public)` 准备输入，客户端无需 LUT 或手工 codec。例如，构造 context 前配置 `PbsMessageConfig::new(16).with_output_modulus(4)`：

```rust,ignore
let encryptor = context.encryptor(external_secret)?;
let decryptor = context.pbs_decryptor(external_secret)?;
let lut = context.pbs_lookup_table_compiler()?.compile_fn(|x| (x % 4) as u64)?;
let input = encryptor.encrypt_padded(7, &mut rng)?;
let output = evaluator.apply_lookup_table(input.as_view(), &lut);
assert_eq!(decryptor.decrypt(output.as_view())?, 3);
```

同一密钥、context 和 evaluator 可保持输入编码，为另一程序选择不同输出模数：

```rust,ignore
let messages = context.parameters().messages().with_output_modulus(8);
let decryptor = context.pbs_decryptor_with_message_modulus(external_secret, messages.output_modulus)?;
let compiler = context.pbs_lookup_table_compiler_with_messages(messages)?;
let lut = compiler.compile_fn(|x| (x % 8) as u64)?;
```

同时更改输入消息域时，使用 `context.encryptor_with_message_modulus(external_secret, messages.input_modulus)` 或 `public_encryptor_with_message_modulus(&public, messages.input_modulus)`，保持配置的密文模数、密钥及噪声采样器。ManyLUT 示例展示复用同一 evaluator 的第二个完整程序。

MVB 消息覆盖使用 `compile_mvb_fn_with_messages(messages, ...)`，配套 `context.ring_return_decryptor(external_secret, messages.output_modulus)` 解码 Scaled 输出。编译器和客户端的覆盖均不改变默认值或已有客户端，也不转换密文编码或建立新的噪声预算。密文不携带消息域元数据：反馈前须确保输出与下一输入的编码、消息模数及程序定义域匹配。即使消息模数相同，完整输出域的结果也可能超出 padded 输入范围。

GLWE 区分小 LWE 的 BR 输入 q 和环/LUT 的 Q：BR→KS 在 q 上输入/返回；KS→BR 在 Q 上输入/返回，内部小 LWE 转换到 q。NTRU 使用环 Q 和外部 q，返回缩放已有相位，不重新生成 q 编码中心。须预算 Q→q 舍入及 KS 噪声，并满足输出 codec 恢复条件。即使 `t_out=t_in`，MVB 仍为 Scaled 输出。

## 编码与密钥契约

| 客户端方法 | 消息含义 |
| --- | --- |
| `encrypt` | `0..t` 内 unsigned 值 |
| `encrypt_padded` | 相同尺度，限制在 `0..ceil(t/2)`，供前半区 LUT 使用 |
| `encrypt_centered` | `0..t` 内代表元，上半区表示负数 |
| `decrypt` | 绑定输出消息域中的规范代表元 |
| `decrypt_phase` | 未解码的相位，供诊断使用 |

Centered 加密不能替代普通 LUT 的 unsigned 输入契约。返回值属于 `0..t_out`，下一次前半区 PBS 只接受 `0..ceil(t_in/2)`。相同消息模数不足以直接反馈，还须匹配编码、已编程域及噪声余量。Rounded 和 Scaled 的编码中心及恢复界不同。

原始密文不记录秘密身份、编码或噪声。调用方须使用配套密钥及显式模数下的规范系数；Fourier 密钥/evaluator 要求同一 FFT 表实例。形状和 LUT 检查不能证明这些事实或安全/噪声预算。直接接收 `LweSecretKeyRef` 的共享客户端构造器也依赖调用方先建立模数兼容性，优先使用接收拥有型密钥的家族/context 工厂。

## Boolean 门

设置 `config.messages = PbsMessageConfig::new(4)`，使用 `boolean_encryptor`、`boolean_public_encryptor`、`boolean_decryptor` 和 `boolean_evaluator`。门串联要求输入输出模数均为四。客户端采用 unsigned Rounded 0/1，拒绝解码出的非 Boolean 值；使用普通 PBS 密钥即可。

`evaluate_binary_to` 使用一次 PBS，`not_to` 不用，`mux_to` 使用两次。输出保持外部 Boolean 编码，可进入后续门。完整示例见 [GLWE](../primus_tfhe_glwe_ntt/examples/ntt_boolean.rs) 或 [NTRU](../primus_tfhe_ntru_ntt/examples/ntru_ntt_boolean.rs)，内部尺度恢复见 [Boolean 契约](src/boolean.rs)。

## CBS 输出与消费

CBS context 提供 `compile_cbs_fn`、`compile_cbs_slice` 和 `compile_cbs_identity`，按 gadget 尺度 `g_j*F(m) mod Q` 编程，覆盖完整 padded `0..ceil(t_in/2)` 域，或 GLWE `MsbBoolean` 的两个 bit；切片必须恰好覆盖该域。通过 `circuit_bootstrap_evaluator_with_lookup_table(&server, program)` 绑定程序，恒等函数可用 `circuit_bootstrap_evaluator(&server)`。兼容函数复用同一密钥。GLWE 输入使用 `context.cbs_encryptor`，两种编码均调用 `encrypt` / `encrypt_to`；MSB Boolean 独立于普通 PBS，使用 t=2。NTRU 仍通过 `context.encryptor` / `encrypt_padded` 准备 padded 输入，不接受 MSB 程序。

CBS 产生累加秘密下的 GGSW/NGSW。`cmux_to` 在零时选择 lhs、一时选择 rhs，因此 **F 在整个已编程域上都必须为 bit**，输入本身无需为 bit。其他规范环整数可由 `external_product_to` 消费，需独立的乘法/噪声预算。控制须匹配 basis、实际秘密和变换表示，候选环密文须共享秘密、模数及编码。

候选使用 `context.accumulator_client(ring_secret, t_ring)`，在累加 Q 下加解密 N 个 Scaled 环系数。t_ring 独立于输入 t 和 gadget 缩放，按候选值及后续环运算选择；这些系数不是独立的 SIMD 槽。复用客户端及 `_to` 方法，完整示例见 [GLWE CBS](../primus_tfhe_glwe_ntt/examples/ntt_circuit_bootstrap.rs) 和 [NTRU CBS](../primus_tfhe_ntru_ntt/examples/ntru_ntt_circuit_bootstrap.rs)。

NTRU 的 `one_hot_evaluator` 使用专用 selector 表；`cmux_k_to` 消费非零 selectors δ₁…δ(M−1)，以 C0 为默认项。见 [one-hot 契约](../primus_tfhe_ntru/README.zh_CN.md#one-hot-cbs)。显式数值组合使用后端底层 `CircuitBootstrapEvaluator` / `OneHotCircuitBootstrapEvaluator`，资源及替代 basis 契约由其 rustdoc 说明。

## 复用 evaluator

重复请求保留 context、密钥和已编译程序。Evaluator 拥有可变 scratch，`_to` 方法复用它及调用方输出；并发 worker 需要独立的可变 evaluator/工作区。按操作优先使用 `context.evaluator`、`mvb_evaluator`、`circuit_bootstrap_evaluator` 和 `one_hot_evaluator`，底层共享方式见后端 API。

## 奇数全域 PBS

`compile_odd_full_domain_fn` / `compile_odd_full_domain_slice` 编程整个 `0..t_in`，要求奇数 `t_in>=3` 且 `t_in<=N`；切片按输入顺序包含 t_in 个输出。用普通 `encrypt` 加密，随后使用已有 PBS evaluator 和对应输出解码器。

折叠后的负循环旋转中心须互不相同，碰撞返回 `RotationCenterCollision`。典型间距为 `N/t_in`，输入余量约为前半区的一半。容量检查不建立失败概率，仍须预算输入误差和逐系数模切误差。该入口只支持单输出，交错和双输入编译器保持前半区契约。见[旋转几何](../../guides/development/bootstrapping-contracts.md#rotation-geometry)。

## 有界双输入 PBS

`BivariateLookupTable::try_new(B, R, poly_length, input_codec, output_codec, function)` 通过 `z=x+B*y` 编程 `f(x,y)`。B、R 均须为正且 `D=B*R<=ceil(t_in/2)`，只编程此前缀，x 优先变化。B 无需为二次幂；输出 t_out 独立，但两 codec 须共用密文模数，此入口不支持 NTRU q≠Q。

复用打包 LWE 和输出，`pack_to` 计算 `lhs+B*rhs`。输入须共享实际秘密、unsigned 输入编码和模数，系数规范且消息在范围内。第二个输入噪声放大 B 倍，q 不被 t_in 整除时还可能引入编码舍入偏差。容量不足以证明噪声余量充分，完整契约见 [BivariateLookupTable](src/lookup_table/bivariate.rs)。

## 固定尺度分解式 MVB

`compile_mvb_fn(D, output_count, function)` 为非空前半区前缀准备 Rounded 输入、unsigned Scaled 输出的程序。系数模数须为显式奇数，或 Native 且**实际 Scaled 输出尺度为偶数**；不支持显式偶模数。t_out 无需为二次幂，回调接收 `(input, output_index)`，外层为输出索引。

所有输出共享一次步长 1 的 BR，再分别乘公开多项式。输出数为正、不补齐，也不降低输入分辨率。整数因子范数放大 BR 噪声，NTRU 因子也放大加密初始化误差，Fourier 还需 FFT 误差预算。Scaled 输出使用 `mvb_decryptor`，反馈给 Rounded 输入 PBS 需另行检查编码和噪声。本实现不提供奇数全域 MVB 或 CBS 输出。

四后端均支持 classic 和 sparse，GLWE 支持两种顺序。[GLWE](../primus_tfhe_glwe_ntt/examples/mvb_thresholds.rs) 和 [NTRU](../primus_tfhe_ntru_ntt/examples/ntru_ntt_mvb_thresholds.rs) 示例产生 17 个阈值标志。ManyLUT 容量及旋转余量足够时优先使用；更多输出且因子范数较小时可考虑 MVB。代数和噪声条件见 [FactorizedLookupTable](src/lookup_table/factorized.rs) 及 [MVB 设计](../../guides/development/bootstrapping-contracts.md#factorized-mvb)。

## 错误边界

配置及绑定使用 `try_*` 工厂，处理其返回的错误类型。`LookupTableError` 负责编译，`TfheEvaluationError` 负责 evaluator 绑定，`ClientError` 负责普通客户端操作，`BooleanError` 负责 Boolean 操作。形状错误可能按方法文档所述 panic；底层原因通过 `std::error::Error::source()` 保留。

## Features 与进一步阅读

默认 features 为空，`simd` 转发给算术依赖。同态求值须选择具体后端。

[API 源码](src/lib.rs) · [参数条件](../../guides/development/tfhe-parameters.md) · [数值契约](../../guides/development/bootstrapping-contracts.md)
