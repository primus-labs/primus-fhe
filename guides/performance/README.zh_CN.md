# 性能取舍与历史证据

[English](README.md) | 简体中文

按当前负载选择专题。**历史耗时不代表当前HEAD验证、安全性或DFR保证。** 导航提供双语，
下表标明正文语言，测量数据只维护一份。现行用法和命令见[开发指南](../development/README.zh_CN.md)
及[基准指南](../development/testing.md#tfhe-benchmarks)。

| 主题 | 正文语言 | 保留价值 |
| --- | --- | --- |
| [BGV 系数与子环槽](bgv-basic.md) | English | 精确 centered 恢复的资源选择与完整 packed 请求基线 |
| [BFV 系数工作流](bfv-leveled-coefficients.md) | English | 精确舍入降模的资源选择与完整系数请求成本 |
| [Sparse算术与调度](sparse-arithmetic.md) | English | 当前聚合、canonical NTT边界、16 KiB tile、4/2/1所有权及负向控制 |
| [NTRU投影](ntru-projection-fusion.md) | English | NTT四策略、Fourier paired/共享成本，以及历史binary完整请求未达门槛的证据 |
| [Fourier GLWE建钥](fourier-glwe-keygen.md) | 中文 | 精确native行修复、旧密钥更换、准备/存储成本与浮点限制 |
| [GLWE平方SS](glwe-square-ss.md) | 中文 | Rank1 NTT材料节省、完整CBS/CMux收益与回退 |
| [PBS/CBS/EBS参考](bootstrap-functional-comparison.md) | 中文 | 历史算法、参数差异及进程均值；旧错误Primus GLWE Fourier时间退出比较 |
| [首项乘积覆盖](fourier-first-write.md) | English | 保留清零后累加的简短历史依据，不作为当前流水线证据 |
| [LUT参数](../../../primus_high_prec_lut/guides/performance/ntru-lut-presets.md) | English | 独立库的逐请求参数和数值边界 |
| [OMR调度](../../../primus_omr/guides/performance/omr-scheduling.md) | English | 独立应用的检测/检索吞吐、worker及工作区成本 |

## 比较与复测

比较相同算法、版本/实际二进制、CPU、feature、参数和完整操作。阶段加速或分配减少不证明
完整请求收益。每次计时一个请求，无关准备/校验移到计时外，构造成本单列，保留不利轮次和
未修改路径控制。单进程区间不能衡量进程间波动。

CPU4/8记录来自**同一台**Ryzen9 9955HX3D的两个L3组，不是独立平台。耗时不能诊断cache写回或带宽；
requested heap、分配流量、峰值及RSS有不同边界。

[数据](data/)保留必要进程摘要、源码/参数身份及选定原始样本。数值/逐方法契约归rustdoc及
[自举指南](../development/bootstrapping-contracts.md)。历史参数名和值不改写成当前预设。
报告标识测量，不承诺独立复现；已删除适配器/ELF不再维护。公开报告不依赖本地`docs/`。

被替代的原始矩阵及重复过程可从Git
`c6a6fcbe8dce15be5df83215611f39bdeda181ba`追溯，例如：

```sh
git show c6a6fcbe:guides/performance/data/fourier-first-write-pairs.csv
```

参数、契约、FFT plan或编译器改变时须重新验证/测量，不能静默替换旧的正向或不利结果。
