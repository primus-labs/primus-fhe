# 性能取舍与历史证据

[English](README.md) | 简体中文

本目录保留选择依据、数值限制和不利测量。**历史结果不代表当前 HEAD 验证或安全保证。**
现行配置和命令见[开发指南](../development/README.zh_CN.md)、
[TFHE 基准](../development/testing.md#tfhe-benchmarks)及
[LUT 基准](../../../primus_high_prec_lut/guides/development/testing.md#high-precision-lut-benchmarks)。

| 报告 | 用途 |
| --- | --- |
| [LUT 参数](../../../primus_high_prec_lut/guides/performance/ntru-lut-presets.md) | 现行 28 组导出范围；LowPrec/HighPrec 选择和未解决的 DFR、split FFT 限制。 |
| [NTRU 投影](ntru-projection-fusion.md) | 策略配置、密钥/scratch 成本、binary 负向门槛和 Fourier 首 pair 共享。历史 gadget 不同于当前预设。 |
| [跨库 PBS/CBS/EBS](bootstrap-functional-comparison.md) | 2026-10-11～13 的库、算法、参数对照，后续 Primus 改进不回填旧排名。 |
| [Sparse 算术](sparse-arithmetic.md) | 分派边界、聚合证据和可复用的多输入批处理内核。 |
| [OMR 调度](../../../primus_omr/guides/performance/omr-scheduling.md) | 独立应用的检测/检索吞吐、worker 调度与工作区开销。 |
| [Sparse 布局与批处理](sparse-layout-and-batching.md) | 四输入调度、旋转描述所有权、tile/流式/布局反例；旧裁剪 LUT 不代表当前完整树。 |
| [Fourier GLWE 建钥](fourier-glwe-keygen.md) | 精确native行修复成本、在线存储不变及旧表示测量的使用边界。 |
| [GLWE 平方 SS](glwe-square-ss.md) | Rank1 NTT 平方材料、完整 CBS/CMux 测量及不变的工作区开销。 |
| [Fourier 首项覆盖](fourier-first-write.md) | 保留清零后累加的依据；54 组有效构建配对包含不利结果及 FFT plan 不一致记录。 |

## 阅读与复测

比较相同版本、实际二进制、CPU、feature、参数和完整操作。仅阶段加速、分配减少或
相同缓冲长度不能证明完整请求收益。每次迭代测一个请求，无关准备/验证移到计时外，
构造成本单列。保留不利轮次和未修改路径的控制组；单进程置信区间不能衡量进程间波动。

历史 CPU4/8 来自**同一台** Ryzen9 9955HX3D 的两个 L3 组，不是独立平台。
耗时不能诊断 cache 写回或带宽；分配流量、保留 heap、峰值和 RSS 是不同口径。

[数据](data/)保留原始样本或紧凑元数据，各有单位及来源。不要为匹配现行 API 而重命名
历史负载或改写参数。它们标识历史测量，不保证独立复现；已删除的适配器/二进制不再维护。
契约变化需要重新验证和完整计时。拟提交报告不依赖本地 `docs/` 或临时源码归档。

数据随仍保留的比较或实现决策维护，不保留每次旧实验。已被替代的NTRU矩阵与单轮参考样本从Git追溯；旧文档中的引用本身不构成保留理由。
