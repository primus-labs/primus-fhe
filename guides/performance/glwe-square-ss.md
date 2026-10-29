# GLWE NTT rank1 平方 scheme switching

[English navigation](README.md) · [中文导航](README.zh_CN.md) · [密钥及噪声契约](../../crates/primus_glwe/src/scheme_switch/ntt.rs)

Rank1 NTT SS 只保存 `GLev(s²)`，以 `sum D(a)GLev(s²)+(b,0)` 生成 mask 行，
并复用输入 body 行的NTT。Rank>1和Fourier保持完整GGSW外积；trace仍独立执行。
不增加策略、参数或workspace类型，既有 `generate/apply_to` 入口不变。
删除body分解不保证逐输入降噪；共享输入误差和平方秘密残差仍须按真实消费者分析。

## 固定负载

2026-10-28，生产基线 `c82f4c83476bae3f2973403b615a639e8d4401e1`，候选为其上的独立平方SS修改。
运行时源码指纹（按路径排序的SHA256映射再散列）：`564810acebf948d776afabdcda686a8859e8c7a0dfa2a19cb79bd0f3a7cb9879`。
两个测量ELF：原实现 `d05bb59916c4e111`，候选 `681640f13d427e8b`。
这是历史测量，不是后续HEAD认证或独立重建承诺；参数未随算术迁入调整。
之后 NTT `CLASSIC_CBS_U64` 已改用 n866/N2048 binary 环秘密及不同 gadget/KS 噪声；
下表保留原 n800/N1024 参数与结果，不能用当前预设重放。当前值见[参数目录](../development/tfhe-parameters.md#noise-by-key-role)。

| 项目 | classic | g1 |
| --- | --- | --- |
| 输入LWE | n800，binary，q=Q50，σ=2.046151696979124e-6q | n571，binary，q=Q54，σ=3.2q/1024 |
| 环 | rank1，N1024，Q50=1125899906826241，ternary，σ6.4 | rank1，N2048，Q54=18014398509404161，binary，σ3.2 |
| BR/trace/SS `(log₂B,L)` | (8,6)/(8,6)/(8,6) | (17,2)/(13,3)/(19,2) |
| 输出 `(log₂B,L)` | (8,2) | (4,4) |
| padded输入/函数 | t8，m3，F=[m≥2] | t4，m1，F=m（合法域0/1） |

key/input/CMux seed为42/1042/2042。平方材料逐位等于旧SSK前缀，控制/body/CMux输出与冻结平方算法一致。
少采未用key行会移动后续返回KS的随机流；不宣称完整keypair逐位相同。两组分别作等参数A/B，不是互相等安全比较。
CPU4/8固定输入检查覆盖padded/MSB、每个gadget行/系数与真实全多项式CMux；小环整数oracle检查完整物理行与残差公式。
这些检查不是完整DFR或安全认证。

## 完整性能与边界

Ryzen9 9955HX3D，CPU4/8是物理核4/8，L3为96/32MiB，SMT sibling20/24。
Rust1.98.1，release/native，未开启nightly simd feature。分别冻结两个ELF，六轮交替运行，
每cell预热≥0.5s、96个单请求样本，13824样本全部保留；计时期间无并发编译或allocation tracking。
CBS包含BR、全部lane完整reverse trace、offset和SS→NTT GGSW；CMux再消费两份真实非零多项式密文。
建钥、编程、加密、分配和校验在计时外，**不含提取/返回KS/MS**。

| 参数 | CPU | CBS 原→平方 ms | 配对变化 | CBS＋CMux 原→平方 ms | 配对变化 |
| --- | ---: | ---: | ---: | ---: | ---: |
| classic | 4 | 14.13484→14.25991 | +0.889% | 14.13949→14.23311 | +0.634% |
| classic | 8 | 13.90471→13.85496 | -0.284% | 13.91487→13.86444 | -0.385% |
| g1 | 4 | 13.08610→13.01790 | -0.453% | 13.12342→13.03848 | -0.571% |
| g1 | 8 | 14.28361→14.24801 | -0.225% | 14.32038→14.28034 | -0.221% |

毫秒列为六个进程中位数的中位数，百分比为六轮配对变化的中位数；负号为快，两列不能直接相除重算。
[逐轮数据](data/glwe-square-ss-2026-10-28.csv)包含全部不利轮次和SS-only诊断。
SS-only热态局部快约38%～43%，不是CBS内插桩时间，不能用它推导完整阶段占比或宣称完整CBS快四成。
完整收益较小且依赖负载/CPU；Classic的回退也保留，不主张所有完整请求都加速。

原GGSW/BR调度保持不变，仅复用现有分解、NTT及模乘加原语。
抽取共用外层循环曾改变代码生成且出现完整回退，未保留；最终通用GGSW内积去地址/RIP位移后与基线逐指令相同。
不同ELF仍可能有代码/数据布局及运行状态差异，未用硬件计数器认定cache或带宽因果。

## 空间与使用

| 指标 | classic 原→平方 | g1 原→平方 |
| --- | ---: | ---: |
| SSK payload | 192→96KiB | 128→64KiB |
| 完整keypair retained requested heap | 158662512→158564208B | 76449256→76383720B |
| evaluator＋resources＋GGSW output | 247856B，不变 | 692320B，不变 |
| 既有EP scratch payload | 33792B，不变 | 67584B，不变 |

SSK减半不代表完整keypair减半。实际retained heap差值等于上述payload减少；没有新在线缓冲或临时key owner。
120次旧/新在线调用审计，alloc/free/realloc及requested live/peak增量均为零。
requested heap不是RSS；进程高水位包含建钥、校验参考及采样缓冲，不作为算法空间差值。
调用方仍绑定 `key.key_size()`，复用原workspace；完整CBS/CMux/返回示例和基准入口见
[GLWE NTT](../../crates/primus_tfhe_glwe_ntt/README.zh_CN.md)及[测试指南](../development/testing.md#tfhe-benchmarks)。
