# 基准口径与性能取舍

[English](README.md) | 简体中文

从仓库根目录运行当前基准，入口见 [BFV/BGV 命令](../development/testing.md#bfvbgv-工作流与基准)和 [TFHE 命令](../development/testing.md#tfhe-benchmarks)。各 crate 维护自己的基准参数和工作负载。

## 测量一个请求

A/B 对照固定算法、输入、参数、编译器、feature、CPU 和实际二进制。分开记录准备、冒烟检查与统计采样。先确定编码、加密、输出分配、LWE 返回和结果校验是否进入计时，再对两个版本使用相同边界。单请求延迟与批量吞吐分开比较，requested heap、分配流量和进程 RSS 分列。部分历史测试绑定同一台 Ryzen 9955HX3D 的两个 L3 核组，结果只描述对应机器和负载。

<a id="bfv-and-bgv"></a>

## BFV 与 BGV

- **BFV 乘法。** 普通入口默认 Exact，HPSPOVERQ 需要显式选择。整数 schoolbook 参考实现用于核对 Exact RNS NTT 的张量和 scale-and-round 结果。两者的耗时比例只适用于这两个实现。HPSPOVERQ 有独立误差项。临时工作基方案保持外部密文基，在有限电路预算内选择内部基。较小的工作密钥可以降低总内存，即使单次操作的 scratch 增大。 [Exact 和 HPSPOVERQ 求值](../development/bfv-evaluation.md) · [临时工作基](../development/bfv-working-basis.md)
- **求值密钥。** Radix 或 Hybrid 密钥的选择独立于 BFV 乘法后端。Hybrid 要同时测量建钥、保留的 QP 材料、可复用 scratch 和完整请求。求值密钥的 P 与 BFV 乘法专用的计算 P 各有用途。 [Native Hybrid 契约](../development/native-hybrid-keys.md)
- **BGV 多级请求。** 对照包含实际的校正因子和降模序列。保持逻辑输入一致，在全部所需旋转、换钥和降模之后检查恢复结果。 [BGV 求值](../development/bgv-evaluation.md#exact-prime-drop-and-logical-message-preservation)

<a id="tfhe-comparisons"></a>

## TFHE 对照

比较相同输出终点。普通 PBS 基准包含配置的返回路径。GLWE 的 `cbs_identity` 对照以可消费的变换域 GSW 为终点，准备阶段用真实的深度一 CMux 检查输入 0 和 1。如果负载需要 CMux 和 LWE 返回，应将它们明确计入。LightFHE G1 和 CMUX2 的派生 profile 是基准用例，输入和消费契约与教学预设不同。历史跨库 PBS、CBS 和 EBS 参数各异，适合作为功能参考。 [对照命令](../development/testing.md#glwe-functional-comparison-benchmarks) · [当前基准参数](../development/tfhe-parameters.md#current-backend-benchmarks)

单输入和批量盲旋转分开测量。保留的 sparse 调度沿用加密 selector、dummy 和算术边界，收益取决于实际几何和工作负载。即使 scheme switching 局部提速或平方密钥 payload 变小，含 CMux 与返回的 CBS 仍需完整测量。 [自举契约](../development/bootstrapping-contracts.md)

<a id="fourier-key-generation"></a>

## Fourier 建钥

Fourier GLWE 求值材料先生成 native 系数行，再进行变换。升级时应重新生成旧未约简路径产生的材料，并更换曾公开受影响材料的秘密。当前 GLWE Fourier 计时以精确系数路径为准。历史修复实验单列准备成本，观察到建钥耗时增加，在线差异较小且方向不一。精确 native 系数行仍有 Fourier 转换误差和后端精度限制。 [Fourier 误差预算](../development/bootstrapping-contracts.md#glwe-fourier-error-budgets)

<a id="ntru-projection"></a>

## NTRU 投影

生成密钥和准备 scratch 前选择投影策略。NTT CBS 性能预设使用 `PairedTrace`，默认配置使用 `Separate`。Fourier 融合和配对要求 split trace 和 scheme switching，NLEV-only 或 dual 输出仍分开执行。历史 NTT 配对实验以更多密钥和 scratch 换取更快的 trace 加换钥投影。Fourier 完整 one-hot 和 LUT 的结果方向不一，局部投影加速有时没有降低请求耗时。选策略时同时比较完整请求与其误差预算。 [投影与精度契约](../development/bootstrapping-contracts.md#ntru-cbs-precision-and-projection-support)

## 历史证据

旧实验报告和数据可在 Git 提交 `c0584af519270022cc704b500db72f3bdbb60cf4` 中查阅，里面记录了原始源码、用例和测量口径。当前基准使用当前源码和参数。当前预设的安全性和解密失败率需要单独验证。

```sh
git ls-tree -r --name-only c0584af5 -- guides/performance
git show c0584af5:guides/performance/bfv-multiplication.md
```
