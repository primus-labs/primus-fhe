# PBS、CBS 与 EBS：历史算法和参数对照

[性能导航](README.zh_CN.md) · [当前基准入口](../development/testing.md#tfhe-benchmarks)

以下是2026-10-12～13的历史参考，不是当前Primus性能排名。所有时间来自同一台Ryzen9 9955HX3D、CPU4、单线程；单位ms，为三个独立进程均值的平均［最小，最大进程均值］，范围不是置信区间。
CBS终点是可消费的变换域GSW，**不含CMux或LWE返回**，另列的CBS＋CMux除外；PBS/EBS包含完整返回。建钥、输入加密、LUT准备与校验在计时外，运行时原有分配保留。

**Primus GLWE Fourier旧建钥材料不满足当前精确系数建钥契约，其全部旧时间已退出比较。** 修复成本见[精确建钥](fourier-glwe-keygen.md)；没有用后来版本回填旧值。外部refined仍可作为参数/功能参考，但没有修复后Primus的同期配对。这一限制不自动适用于NTT或NTRU。

[进程数据](data/bootstrap-comparison-processes.csv)保留102条完整操作均值，含记录过的两个bit与全部轮次；[证据元数据](data/bootstrap-comparison-evidence.json)集中版本、参数、采样、实际消费者及原始数据的Git恢复身份。旧适配器、补丁、锁和ELF并非公开复现包，checkout某个上游commit或运行当前bench不能重建旧实验。
同一进程可报告不同操作/bit，102行不是102个独立进程；每张表的范围仍来自对应三次独立运行。

下文分解记作`(L,b)=(level_count,log₂B)`，Low/High仅是当时的分解配置名，不是现行输入位宽或DFR30/128标签。同层数/基数、相同N或一次消费成功，都不建立同安全性或同完整DFR。

<a id="glwe-trace-cbs"></a>
## GLWE：BR、trace 与 scheme switch

| 历史实现 | CBS bit1→GSW | CBS＋CMux | 配对范围 |
| --- | ---: | ---: | --- |
| LightFHE `7681a6ac`，原sampler | 82.087 [82.043,82.110] | 未测 | G1 NTT |
| LightFHE，同commit、修正截断表达式 | 81.127 [81.065,81.162] | 未测 | 改变采样支持及RNG消耗，单列 |
| Primus `5fc1a932`，NTT | 13.124 [13.034,13.211] | 13.139 [13.086,13.191] | G1派生协议，非当前预设 |
| refined `9b0426e8`，CMUX2 ordinary | 8.734 [8.693,8.812] | 8.715 [8.653,8.765] | G2 Fourier，未配对参考 |
| refined，同commit、CMUX3 split | 9.147 [9.100,9.235] | 9.217 [9.122,9.275] | G2低35/高29 trace，未配对参考 |

“CMUX2/3”是作者参数组名，不是计时内CMux次数。CBS与组合独立采样，不能相减推导CMux耗时。
G1虽有明显成本差异，仍同时包含算法、密钥结构、变换、编译器和分配的影响，不能全归于某个优化。

| 参数/流程 | G1：LightFHE与历史Primus NTT | G2：refined参数参考 |
| --- | --- | --- |
| 小LWE / rank / N / Q | n571 / 1 / 2048 / 18014398509404161（Q54） | n636 / 1 / 2048 / native64 |
| 实际输入 | q1024、MSB中心0/512，无输入KS | 外部n2048/native64、MSB中心0/2⁶³，经scalar KS到636维 |
| 小/环秘密 | 独立dense binary | 独立dense binary |
| BR / trace / SS / 输出 | (2,17)/(3,13)/(2,19)/(4,4) | (2,15)/(6,7)/(2,17)/(4,4)，输入KS(5,2) |
| 输入/环行噪声 | 声明σ3.2；Light原版支持±4、corrected±39，Primus CDT±38 | 环/新鲜外部βQ=17065.45141033878；KS αQ=1706545141033878 |
| 算法差异 | Light：/N后forward trace、RLWE[s²] SS；旧Primus：逐层reverse trace、Full GGSW[−s] SS | rounded continuous Gaussian；forward trace；ordinary或split trace，BR/SS ordinary |

G1的centered-Q digits、奇数gadget权重、LUT幅度与Primus二进制权重/carry仍不同；保护区也不同。原Light实现还受C++17 signed-left-shift未定义行为限制，结果只标识GCC15.2当前产物。后续Primus rank1已采用[平方SS](glwe-square-ss.md)，不能把旧时间改名为该实现。
G2历史Primus使用ring KS，refined使用scalar KS；它们不是同一密钥的存储重排。当前输入域和输出合同见[自举契约](../development/bootstrapping-contracts.md#ordinary-cbs-and-consumption)。

G1/G2采用真实t8、深度1消费者检查；finite checks不证明全部名义gadget位数或深层CMux精度。历史CMUX1及Light CMUX3曾出现真实消费失败，不借其他参数组的时间填空；元数据保留实际支持和验证边界。

<a id="glwe-private-ks-cbs"></a>
## GLWE：外部CBS功能参考

以下均未与Primus同协议配对。TFHEpp annihilate属trace/SS家族；ordinary和MOSFHET属private/packing KS家族，不能只按环长度排名。

| 实现 | BR环 `(N,k,Q)` / `(L,b)` | 输出环 / gadget | 在线输入KS | CBS bit1→GSW |
| --- | --- | --- | --- | ---: |
| TFHEpp block annihilate | (1024,2,2⁶⁴)/(4,10) | 同BR；trace/SS(5,9) | (5,2)，subset | 9.349 [9.259,9.487] |
| TFHEpp dense annihilate | (2048,1,2⁶⁴)/(4,9) | 同BR；trace/SS(5,9) | (7,2)，subset | 16.172 [16.063,16.371] |
| TFHEpp block ordinary | (1024,2,2⁶⁴)/(4,10) | (1024,1,2³²)/(4,6) | (5,2)，独立scalar | 43.040 [41.881,43.743] |
| TFHEpp dense ordinary | (2048,1,2⁶⁴)/(4,9) | (1024,1,2³²)/(3,6) | (7,2)，独立scalar | 42.324 [40.695,44.922] |
| MOSFHET ordinary | (2048,1,2⁶⁴)/(4,9) | 同BR | 无 | 207.138 [206.461,207.554] |
| MOSFHET multi_value | 同上 | 同上 | 无 | 153.849 [153.539,154.222] |
| MOSFHET ring_private | 同上 | 同上 | 无 | 81.010 [80.424,81.929] |

TFHEpp外部n1024/native32，内部n630/native16；block秘密是ell2 block binary，dense为iid binary。annihilate采用共享前缀subset秘密，不是独立秘密。BR环秘密ternary、行σ8192；ordinary输出σ约147.033/128，private KS(8,3)。
MOSFHET外部n632/native64、独立dense binary，输入σ2⁴⁹，环秘密dense binary、行σ2²⁰；private/body packing KS(8,4)，ring_private两把环函数密钥(10,4)。unsigned预乘密钥与TFHEpp signed gadget不同。
两库只验证t8、深度1消费，部分低层行残差超过最低gadget权重；不能据名义位数推可用精度。TFHEpp原版参数不变；MOSFHET使用记录过的确定性熵适配补丁，非生产随机性声明。

<a id="glwe-pbs"></a>
## 普通GLWE PBS：4→4位完整返回

固定函数`((13*m) XOR (m>>2)) & 15`，计时输入13→10，全部16输入另行验证。共同u64、n1024/固定binary h128、独立binary环秘密、rank1/N4096、classic BR→KS。

| 实现 | Low | High |
| --- | ---: | ---: |
| TFHE-rs artifact `e1f5d362`，Fourier | 44.957 [44.593,45.425] | 87.223 [85.303,89.863] |
| Primus `354d1db8`，NTT Q50派生 | 65.949 [64.408,66.748] | 136.248 [133.697,137.740] |

Low BR/KS=(4,10)/(6,3)，High=(9,5)/(9,2)。外部native64、padded4、Δ=2⁵⁹；NTT用Q50=1125899906826241、Rounded t32。外部输入/KS σ=3.2×2⁴⁰，NTT为3.2Q50/2²⁴；环行σ均1.5，但归一化噪声不同。
外部提取后scalar KS，Primus ring KS后compact提取。外部在这两组完整请求均更快；模数、返回算法、采样与工具链仍不同，不是同安全/DFR比较，也未分离BR/KS/FFT贡献。

<a id="ebs8"></a>
## EBS：8→4位完整返回

同函数、输入171→5、x=0…255，双方执行完整约定路径，不利用函数周期。当前[lookup_ebs8](../../../primus_high_prec_lut/benches/lookup_ebs8.rs)不是旧测量快照。

| 实现 | Low | High |
| --- | ---: | ---: |
| TFHE-rs artifact，LY23（GLWE） | 142.050 [141.739,142.452] | 284.949 [281.195,287.824] |
| Primus NTRU NTT，one-hot LUT | 75.301 [75.084,75.498] | 129.758 [128.911,130.414] |
| Primus NTRU TFHE-FFT，one-hot LUT | 60.077 [59.936,60.347] | 101.447 [100.031,102.496] |

- 外部单个native64 padded8输入→padded4输出，GLWE rank1/N4096、binary环秘密、行σ1.5；η4、W64，串行4096次GGSW外积。
- Primus两个q52/t32输入→一个q52/t32输出，M16/c2/d2/o1；NTRU N4096，NTT Q50/σf,g=1，Fourier native64/σf,g=1.5。无高chunk选表树，不能代表c>d的大规模查表。
- 小秘密共同n1024/binary h128；归一化输入/KS σ均3.2×2⁻²⁴，独立RNG。Low/High BR和KS同上一节；NTRU trace=(6,7)/(15,3)，SS=(6,8)，selector=(2,10)/(1,17)。返回包括各自实际KS。

这里比较的是具体成本；输入协议、环秘密、模数、误差传播和算法不同，不把比值当同安全/DFR算法加速。High双方及外部Low有独立全256输入诊断，计时进程另检查代表输入；有限验证不估计极低DFR。

<a id="ntru-primitives"></a>
<a id="historical-pbs"></a>
<a id="wide-lut"></a>
<a id="lut-stages"></a>
## 缺口与当前使用

没有通过同用途验证的外部NTRU CBS或同规模c4～c8 LUT配对；旧自身Low/High与单轮排名不继续维护。现行逐c/o/DFR预设与数值限制归[独立LUT库](../../../primus_high_prec_lut/guides/performance/ntru-lut-presets.md)。
旧阶段计时入口已撤回，不承诺重跑；阶段均值不能相加替代完整请求。候选安全成本、完整DFR与消费深度必须独立评估，不能从原库配置名或成功PBS转移。

历史工具链为Primus Rust1.98.1/LLVM22、refined/TFHE-rs nightly-2025-01-01/LLVM19及记录的兼容补丁；C++ GCC15.2/native，Light无HEXL。只绑CPU4，未隔离SMT sibling20/后台活动。各库独立采样，FFT plan和采样器不同，不能把差距归因于某条SIMD指令。
原始逐次时间、过时Primus Fourier排名及巨大基线元数据从Git `c6a6fcbe`追溯；本页只维护仍有用的算法/参数参考与[进程证据](data/bootstrap-comparison-evidence.json)。
