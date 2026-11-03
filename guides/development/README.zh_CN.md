# 库使用导航

[English](README.md) | 简体中文

> [!WARNING]
> [Primus FHE](../../README.zh_CN.md) 是实验性项目；其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

从拥有目标运算的最低层开始。完整 TFHE 应用优先阅读后端示例，按需使用底层组合接口。OMR 与高精度查表是同级独立仓库，以下链接采用该目录布局。Core 库见 [workspace 导航](../../README.zh_CN.md#workspace-导航)。

## 选择入口

| 需求 | 入口 |
| --- | --- |
| 模数、算术与 gadget 分解 | [primus_modulus](../../crates/primus_modulus/README.zh_CN.md)、[primus_reduce](../../crates/primus_reduce/README.zh_CN.md)、[primus_decompose](../../crates/primus_decompose/README.zh_CN.md) |
| 存储、多项式与变换 | [primus_shape](../../crates/primus_shape/README.zh_CN.md)、[primus_data](../../crates/primus_data/README.zh_CN.md)、[primus_poly](../../crates/primus_poly/README.zh_CN.md)、[primus_ntt](../../crates/primus_ntt/README.zh_CN.md)、[primus_fft](../../crates/primus_fft/README.zh_CN.md) |
| 密文布局与算术 | [primus_lattice](../../crates/primus_lattice/README.zh_CN.md) |
| 消息、编码与 phase 诊断 | [primus_encoding](../../crates/primus_encoding/README.zh_CN.md) |
| 独立加密与 key switch | [LWE](../../crates/primus_lwe/README.zh_CN.md)、[GLWE](../../crates/primus_glwe/README.zh_CN.md)、[NTRU](../../crates/primus_ntru/README.zh_CN.md) |
| RNS 转换、raw GLWE 与 gadget 求值 | [primus_rns](../../crates/primus_rns/README.zh_CN.md)、[primus_glwe_rns](../../crates/primus_glwe_rns/README.zh_CN.md) |
| BFV 系数/槽加密、精确乘法、relin、旋转与层级 | [primus_bfv](../../crates/primus_bfv/README.zh_CN.md) |
| BGV 系数/槽加密、乘法、relin、旋转与层级 | [primus_bgv](../../crates/primus_bgv/README.zh_CN.md) |
| PBS、ManyLUT、MVB、CBS 与 Boolean 门 | [运算选择](../../crates/primus_tfhe/README.zh_CN.md)，然后阅读 [GLWE NTT](../../crates/primus_tfhe_glwe_ntt/README.zh_CN.md)、[GLWE Fourier](../../crates/primus_tfhe_glwe_fourier/README.zh_CN.md)、[NTRU NTT](../../crates/primus_tfhe_ntru_ntt/README.zh_CN.md) 或 [NTRU Fourier](../../crates/primus_tfhe_ntru_fourier/README.zh_CN.md) |
| One-hot selectors | [NTRU CBS 与 one-hot](../../crates/primus_tfhe_ntru/README.zh_CN.md#one-hot-cbs)，然后阅读后端示例 |
| 加密多 chunk 整数上的函数 | [高精度查表](../../../primus_high_prec_lut/README.zh_CN.md) |
| OMR 检测、digest 与恢复 | [primus_omr](../../../primus_omr/README.zh_CN.md) |

## 跨库阅读顺序

阅读目标库的示例后，按组合需求选择以下专题。精确布局、检查和 scratch 契约仍以 rustdoc 为准。

导航提供中英双语，下表标明专题正文语言；外部工具使用其各自的语言入口。

| 主题 | 指南 |
| --- | --- |
| 数值域、表示、借用、phase 与可复用状态 | [跨库组合](composition.md)（English） |
| 原生 BFV/raw GLWE 的组件符号、密钥与显式桥接 | [RNS phase 约定](rns-phase-conventions.md)（English） |
| 原生 BFV 整数 tensor、精确缩放、unscaled keys 与 degree 生命周期 | [BFV 求值](bfv-evaluation.md)（English） |
| 原生 BGV key roles、p-preserving gadget residual 与精确 prime drop | [BGV 求值](bgv-evaluation.md)（English） |
| 旋转舍入、q/Q 返回、CBS 精度/投影支持、Fourier 预算与 one-hot 误差条件 | [自举数值契约](bootstrapping-contracts.md)（English） |
| 当前实验配置及其证据边界 | [TFHE 参数目录](tfhe-parameters.md)（English） |
| 离线 NTRU CBS 噪声场景与 gadget 筛选 | [参数分析工具](../../../primus_high_prec_lut/tools/parameter_selection/ntru_cbs/README.zh_CN.md) |
| 测试、示例、feature 与 benchmark 命令 | [测试指南](testing.md)（中文） |

性能取舍与测量见[性能指南](../performance/README.zh_CN.md)，开发规范见 [AGENTS.md](../../AGENTS.md)。

## 常见陷阱

- 维数或缓冲区长度相同，不证明秘密、模数、basis 或变换身份一致。
- 借用视图不转换表示，也不验证系数。批量数据使用多项式/密文语义迭代器，在入口检查完整长度与配对数量。
- 构造成功不证明安全性或完整运算的噪声余量；实验配置只是功能样例。
- 重复调用前分配 evaluator 与输出，遵循覆盖/累加契约，并发请求各自使用独立可变状态。
