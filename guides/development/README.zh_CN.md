# 库使用导航

[English](README.md) | 简体中文

> [!WARNING]
> [Primus FHE](../../README.zh_CN.md) 是实验性项目。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

从 [workspace 导航](../../README.zh_CN.md#workspace-导航) 查找 crate 和示例。跨 crate 组合时，按任务查阅以下指南。

## 跨库阅读顺序

精确布局、检查和工作区要求以接口的 rustdoc 为准。下表标明专题正文语言。

| 任务 | 指南 |
| --- | --- |
| 选择算术域、借用多项式或密文视图、复用工作区 | [跨库组合](composition.md)（英文） |
| 选择 TFHE 参数、组合运算输出或绑定 CBS 精度与投影 | [参数目录](tfhe-parameters.md)、[自举契约](bootstrapping-contracts.md)（英文） |
| 绑定 BFV/BGV context 和 level，或为其他方案导入 raw 密文 | [方案绑定](scheme-context-binding.md)（中文）、[RNS phase 约定](rns-phase-conventions.md)（英文） |
| 持久化公共参数、密文和求值密钥 | [公共对象持久化](public-storage.md)（中文） |
| 选择 BFV 乘法路径或准备临时工作基 | [BFV 求值](bfv-evaluation.md)（英文）、[临时工作基](bfv-working-basis.md)（中文） |
| 跟踪 BGV 的校正因子和降模 | [BGV 求值](bgv-evaluation.md)（英文） |
| 构建 BFV/BGV 原生 Hybrid 密钥或组合 collective 密钥角色 | [原生 Hybrid 密钥](native-hybrid-keys.md)（英文） |
| 选择 BFV/BGV 参数、核对电路预算与安全参考 | [参数与预算入口](ordinary-parameter-budgets.md)（中文） |
| 运行测试、示例、feature 检查和基准 | [测试指南](testing.md)（中文） |

测量口径与性能取舍见[性能指南](../performance/README.zh_CN.md)。开发规范见 [AGENTS.md](../../AGENTS.md)。
