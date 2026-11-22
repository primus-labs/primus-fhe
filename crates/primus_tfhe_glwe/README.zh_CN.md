# primus_tfhe_glwe

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) 工作区。API 和数值契约尚未稳定，后续可能发生不兼容变更。

GLWE-TFHE 共用的参数和 LWE 客户端。求值与完整示例见 [NTT](../primus_tfhe_glwe_ntt/README.zh_CN.md) 或 [Fourier](../primus_tfhe_glwe_fourier/README.zh_CN.md)。

## 实验配套参数

从后端的 `experimental::*_U64` 配置开始，使用 `try_from_pbs_config` 或 `try_from_cbs_config` 准备 context。`PbsConfig` 设置 BR、KS、PBS 顺序和消息域。`CbsConfig` 还设置 gadget 分解、CBS 输入编码和 trace 精度。

两种配置都包含 `key_switching`。用 `PbsMessageConfig::new(t_in).with_output_modulus(t_out)` 独立选择消息模数。教学参数的安全性及失败概率尚未评估。 [参数条件](../../guides/development/tfhe-parameters.md#scope-of-paired-parameter-entries)

## 参数与外部密钥域

`small_lwe.cipher_modulus` 选择 BR 的小 LWE 输入模数 q。`ring_modulus` 选择 accumulator 与 ring KS 使用的 Q。小 LWE 维数 n 不超过展平环秘密的长度 kN，系数类型须能表示 `2N`。两种顺序都返回各自外部秘密和模数下的 LWE。

| PBS 顺序 | 外部 LWE | KS 位置 |
| --- | --- | --- |
| `BootstrapKeyswitch` | 小秘密，维数 n，q | BR 后 |
| `KeyswitchBootstrap` | 展平的环秘密，维数 kN，Q | BR 前 |

用 `client.external_lwe_secret_key()` 创建客户端，用 `context.allocate_lwe_ciphertext()` 按顺序分配密文。BR 和 KS 噪声按各自的系数单位独立配置。KS→BR 的新鲜外部加密使用 Q 下的环/BR 噪声采样器。 [参数](src/parameters.rs) · [密文域与返回](../../guides/development/bootstrapping-contracts.md#ciphertext-domains-and-return) · [各密钥的噪声](../../guides/development/tfhe-parameters.md#noise-by-key-role)

## 盲旋转密钥

Classic 和 Block 在两种顺序下都支持 PBS、ManyLUT、MVB 与 CBS。Block 使用 `BlindRotationMethod::Block` 和 `SecretKeyDistr::BlockBinary { block_size, occupancy }`。块宽整除小秘密的逻辑长度，ring KS 的公开零尾不参与分块。导入原始系数材料参见 Block 密钥的 rustdoc。 [算法选择](../primus_tfhe/README.zh_CN.md#选择盲旋转算法) · [Block 材料](src/block.rs) · [原始 BR 量化](../primus_tfhe/src/rotation.rs)

## 客户端与 LUT

用 `context.try_generate_keys(rng)` 生成配套密钥。输入使用 `context.encryptor` 或 `public_encryptor`，Rounded PBS/ManyLUT 输出用 `pbs_decryptor` 解码，Scaled MVB 输出用 `mvb_decryptor`。context 工厂从消息配置派生 codec。只负责 LWE 加解密的客户端可直接使用 `PbsParameters` 上的同名工厂，无需加载变换表。公钥加密的额外噪声也需计入输入预算。 [输出编码及覆盖](../primus_tfhe/README.zh_CN.md#选择输出编码) · [公钥加密](../primus_lwe/README.zh_CN.md#公钥加密)

## Boolean 与 CBS

普通 Boolean 门要求 q=Q、输入输出 t=4 及普通 PBS 密钥。CBS 在 CBS context 上调用 `try_generate_circuit_bootstrap_keys`。密钥包的 `server.server_key()` 也可用于 PBS。KS→BR 用 KS 准备 CBS 输入。CBS 输出环秘密下的 gadget 控制密文。

`CbsConfig::input_encoding` 可选 `Padded`（继承 PBS 输入 t）或 `MsbBoolean`（t=2）。用 `cbs_encryptor` 或 `cbs_public_encryptor` 加密外部输入。`br_control_codec()` 对应内部小 q 域。用 `compile_cbs_fn` 编译谓词，再由 `circuit_bootstrap_evaluator_with_lookup_table` 绑定。`accumulator_client(client.glwe_secret_key(), t_ring)` 准备 Scaled CMux 候选。 [CBS 工作流](../primus_tfhe/README.zh_CN.md#cbs-输出与消费) · [CBS 数值契约](../../guides/development/bootstrapping-contracts.md#ordinary-cbs-and-consumption)

`FourierTracePrecision::Ordinary` 适用于两个后端。`Split35` 只改变 Fourier trace，要求 `split-trace` feature、native u64、rank one 且环秘密系数绝对值不超过 1。 [Fourier 数值限制](../../guides/development/bootstrapping-contracts.md#glwe-fourier-error-budgets)

## Features 与进一步阅读

默认无 feature。`simd` 转发至算术依赖。求值使用具体的 NTT 或 Fourier 后端。 [API 源码](src/lib.rs) · [共用操作与编码](../primus_tfhe/README.zh_CN.md)
