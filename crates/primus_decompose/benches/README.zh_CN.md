# primus_decompose 基准

[English](README.md) | 简体中文

> [!WARNING]
> [Primus FHE](../../../README.zh_CN.md) 是实验性项目；其 API 和数值契约可能发生不兼容修改。

## 工作负载与命令

[`decompose`](decompose.rs) target 将 basis 构造与在线分解分开测量：

| 分组 | 每次迭代测量的工作 |
| --- | --- |
| `decompose/primitive/setup`、`decompose/big/setup` | 构造并释放一份 basis |
| `decompose/primitive/online`、`decompose/big/online` | 初始化一个值或一批输入，并提取所有保留层 |
| `decompose/pbs/` | 按 GLWE/NTRU 外积配置分解一个多项式：`init` 测初始化，`levels` 提取所有保留层，`full` 测两者合计 |

```text
cargo bench -p primus_decompose --bench decompose
cargo bench -p primus_decompose --bench decompose -- --test
cargo +nightly bench -p primus_decompose --bench decompose --features simd
```

参数与缓冲区准备以基准源码为准。BigUint 在线案例测量 DCRT 消费者使用的紧凑 radix 编码 digit，覆盖固定 stride 1/2/4 和 runtime stride 3。在线案例复用存储，`levels` 在计时外恢复初始 carry。

`pbs` 分组采用固定的历史分解配置，独立于当前 TFHE 预设。这些测量只覆盖分解，不代表完整外积或 PBS；分阶段耗时相加不能代替实测 `full`。
