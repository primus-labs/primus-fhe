# BFV/BGV 普通工作流与资源整理

测量日期：2026-11-03。基线为 `6562dda676a7fd30c2ead9002c22ebb08eb4c58d`，
新版本为该提交上的接口整理工作树；两者实际编译 artifact、当前源码 SHA、参数、
工具链和全部 240 个样本保存在[数据](data/bfv-bgv-api-workflows-2026-11-03.json)
及[CSV](data/bfv-bgv-api-workflows-2026-11-03.csv)。这是一次具体负载的测量，
不构成其他机器或参数的加速保证。

## 保留的接口设计

普通请求使用 `BfvMultiplication` / `BgvMultiplication`：由重线性化 key 推导
level，拥有并复用中间 quadratic 与求值 scratch，提供 `multiply_to`、`square_to`
和 `square_assign`。单个算法内核仍由原乘法/重线性化实现拥有，没有第二份数学实现。
高级分阶段操作继续可用；独立 schoolbook、raw 阶段和密钥列诊断留在私有测试，
不为基准提供额外默认 public API。

BFV 的自动 P 只准备计算资源：在 setup 中选择满足 NTT 条件且与 Q 互素的 60-bit
素数，精确检查 P>NQ；不改变密文、secret 或 key 的模数。下面的对照保留原显式 P，
隔离普通请求组合的变化；不据此声称自动 prime search 的 setup 最优。

## 完整 fresh 槽请求

N1024/n256、113 active slots、p12289、Q150-bit、radix log8、三层及 sigma0.849
均保持原值。计时包含编码、两次公钥加密、密文乘法/square/两次 relin、旋转、
Alice→Bob 换钥、两次 prime drop、恢复与解码。构造、建钥、缓冲分配和结果断言
在计时外。BFV 和 BGV 使用各自原 Q 链，不作跨方案速度归因。

每方案独立 ABBA 四个进程，每进程 30 samples，warmup1s/measurement3s，
CPU affinity 0、单 Rayon worker、stable native release、无 SIMD。所有构建和其他
验证在采样前结束。每个 artifact 的同负载 smoke 通过，测量前后源码和 binary SHA
保持不变。

| 方案 | 旧进程均值（ms） | 新进程均值（ms） | 旧平均→新平均 | 变化 |
| --- | --- | --- | --- | --- |
| BFV | 1.35236 / 1.32291 | 1.29030 / 1.28775 | 1.33763→1.28903 ms | −3.63% |
| BGV | 0.45769 / 0.45811 | 0.45515 / 0.45968 | 0.45790→0.45741 ms | −0.11% |

本次未观察到完整请求回退。BGV 变化可视为测量波动；BFV 的本机结果也不作为固定
加速承诺。保留全部进程和样本，不用单个最快数值替代整体。

## 预备乘法资源

另以系统 allocator 的请求字节计数隔离 `mul→relin→square→relin`：在 owner
构造前准备相同 context、clients、keys、密文输入与结果输出，使用上述 N/Q/P。
旧 BFV 是 multiplier+relinearizer+quadratic，新 BFV 是组合 owner；旧 BGV 是
带 plaintext scratch 的 evaluator+relinearizer+quadratic，新 BGV 无闲置 plaintext。

| 资源 | BFV 旧→新 | BGV 旧→新 |
| --- | --- | --- |
| owner 存活 heap / 构造额外峰值 | 803496→803496 bytes | 181296→156720 bytes |
| owner inline 大小 | 712→712 bytes | 296→272 bytes |
| setup allocation 次数 | 49→49 | 9→8 |
| 在线 allocation / 额外 peak / live delta | 均为 0 | 均为 0 |

两方案的旧/新输入与最终 ciphertext bytes 均逐字节相同，恢复值通过独立 slot
预期检查；owner drop 后 live bytes 回到构造前。BFV 没有增加这项请求的存储；
BGV 减少 24576 heap bytes。它不是完整 leveled 链峰值、RSS、allocator usable size
或栈峰值，也没有把旧 reference benchmark 的诊断 owner 算进正常请求。

现行命令与数值条件见 [BFV 求值](../development/bfv-evaluation.md)、
[BGV 求值](../development/bgv-evaluation.md)及两个 crate README。可用当前公共
benchmark 重新测量完整请求：

```sh
cargo bench -p primus_bfv --bench multiplication --features batching -- bfv_leveled_slots
cargo bench -p primus_bgv --bench leveled --features batching -- bgv_leveled_slots
```

参数、编译器、流程或默认 P 改变后，需要新测量，不能将本记录当成当前 HEAD 验证。
