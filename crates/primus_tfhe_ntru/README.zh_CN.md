# primus_tfhe_ntru

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) 工作区。API 和数值契约尚未稳定，后续可能发生不兼容变更。

NTRU-TFHE 共用的参数和外部 LWE 客户端。求值与完整示例见 [NTT](../primus_tfhe_ntru_ntt/README.zh_CN.md) 或 [Fourier](../primus_tfhe_ntru_fourier/README.zh_CN.md)。

## 实验配套参数

从后端的 `experimental::*_U64` 配置开始。PBS、ManyLUT 和 MVB 用 `TfheContext::try_from_pbs_config`，CBS 和 one-hot 用 `try_from_cbs_config`。两种配置都包含返回 `key_switching`。用 `PbsMessageConfig::new(t_in).with_output_modulus(t_out)` 独立选择输入和输出消息模数。教学参数的安全性及失败概率尚未评估。 [参数条件](../../guides/development/tfhe-parameters.md#scope-of-paired-parameter-entries)

## 参数与密钥域

`external_lwe` 选择外部秘密 s、维数 n 和模数 q。`ring_modulus`、`bsk_poly_length` 及 `bsk_secret_distr` 选择 Q 下的 accumulator 环和秘密 f。n 与 N 独立，`2N` 须能由系数类型表示。只有 f 需要通过 NTRU 可逆性和 Fourier 逆稳定性筛选。完整建钥还要求 f 的系数绝对值小于显式 q。

外部 LWE、BSK 和返回 KS 的噪声都使用各自模数下的系数单位。BSK 噪声也用于环候选加密、trace 和 scheme-switch 密钥。BR 和返回 KS 噪声独立配置。 [参数 API](src/parameters.rs) · [各密钥的噪声](../../guides/development/tfhe-parameters.md#noise-by-key-role)

## 盲旋转算法

Classic 支持二进制及三元外部秘密，包括固定重量二进制。直接分块聚合使用 `BlindRotationMethod::Block` 和 `SecretKeyDistr::BlockBinary { block_size, occupancy }`。首块用 NLEV 提升公开 LUT，即使首块为空或其旋转指数为零也要执行。后续块使用 NGSW。Fourier Block 要求 u64，支持 ordinary 和 split BR。 [Block 材料](src/block.rs) · [首次提升](../../guides/development/bootstrapping-contracts.md#ntru-first-lifting)

## 客户端与 LUT

用 `context.try_generate_keys(rng)` 生成配套密钥，把 `client.external_lwe_secret_key()` 传给客户端工厂。PBS/ManyLUT 的 Rounded 输出用 `pbs_decryptor`，MVB 的 Scaled 输出用 `mvb_decryptor`。前半区程序用 `encrypt_padded`，奇数全域程序用 `encrypt`。只负责 LWE 加解密的客户端可直接使用 `PbsParameters` 上的同名工厂，无需加载变换表。`public_encryptor` 使用 q 下的 LWE 公钥，需计入公钥输入噪声预算。 [输出编码及覆盖](../primus_tfhe/README.zh_CN.md#选择输出编码) · [公钥加密](../primus_lwe/README.zh_CN.md#公钥加密)

## CBS 与示例

用 `try_generate_circuit_bootstrap_keys` 生成 CBS 材料，密钥包的 `server.server_key()` 也可用于普通 PBS。使用带 padding 的输入，用 `compile_cbs_fn` 编译函数，再由 `circuit_bootstrap_evaluator_with_lookup_table` 绑定。输出是 f 下 gadget 尺度的 NGSW。CMux 使用 bit 函数，并通过 `accumulator_client(client.accumulator_ntru_secret_key(), t_ring)` 在独立的 Scaled 消息模数下加密候选。 [CBS 工作流](../primus_tfhe/README.zh_CN.md#cbs-输出与消费)

在准备 context 和密钥前选择投影和 Fourier 精度。融合策略只作用于 NGSW 输出，NLEV 和双输出按配置精度分别执行 trace 和 scheme switch。相同秘密下的 scheme switch 需要有依据的密钥相关消息安全假设。 [投影和精度矩阵](../../guides/development/bootstrapping-contracts.md#ntru-cbs-precision-and-projection-support) · [相同秘密下的 scheme switch](../primus_ntru/README.zh_CN.md#同一秘密下的-scheme-switching)

## One-hot CBS

用 `context.one_hot_evaluator(&server)` 复用 CBS 密钥包。M 为至少 2 的二次幂，输入模数取 t=2M，再用 `encrypt_padded` 加密 `0..M`。若输出有 L 层 gadget 且 W=next_power_of_two(L)，需满足 2MW≤N，并有足够的相位余量。 [选择区间](../../guides/development/bootstrapping-contracts.md#one-hot-cbs)

为 `cmux_k_to` 使用 `allocate_nonzero_ngsw_output` 和 `one_hot_nonzero_ngsw_to`。该方法消费编号 1 到 M−1 的 selector，默认选择候选 C0。NLEV 单输出和双输出提供系数域 NLEV，使用前需变换到相应域，再与公开多项式相乘。`selector(r)` 接受分支的数学编号。 [Selector 布局](src/one_hot/selectors.rs)

Block 可用 `new_pair_workspace` 和 `with_pair` 成对求值，在回调内消费每个 selector 视图。Classic 和最后一个单独输入使用单输入方法。没有前置 CMux 层执行公开提升时（c=d），Block 或 split BR 需用 `try_generate_public_lift_key` 生成独立的 `NLEV[1]`。Fourier 使用 ordinary lift 材料执行该乘积。 [Block 密钥契约](src/block.rs) · [NTT 建钥](../primus_tfhe_ntru_ntt/src/key.rs) · [Fourier 建钥](../primus_tfhe_ntru_fourier/src/key.rs)

## NTRU→LWE 返回

PBS evaluator 依次执行逐系数 Q→q 舍入、相位提取和 LWE KS，返回 q 下秘密 s 的密文。返回缩放已有相位，需计入编码尺度差。独立的系数域环结果用此处重导出的 `LweReturnEvaluator`，批量调用用 `LweReturnBatchWorkspace`。 [返回 API 和数值契约](../primus_ntru/README.zh_CN.md#独立-lwe-返回) · [密文域](../../guides/development/bootstrapping-contracts.md#ciphertext-domains-and-return)

## Features 与进一步阅读

默认无 feature。`simd` 转发至算术依赖。求值使用具体的 NTT 或 Fourier 后端。 [API 源码](src/lib.rs) · [共用操作与编码](../primus_tfhe/README.zh_CN.md)
