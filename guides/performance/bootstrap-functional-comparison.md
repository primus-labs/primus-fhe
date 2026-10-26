# PBS、CBS 与 EBS：历史跨库比较

本页保留 2026-10-11～13 的跨库比较：先按算法找到外部库与 Primus，再看同表参数差异。
这些版本早于后续 Fourier 内核、NTRU 投影和逐请求参数改进，**不代表当前 HEAD 的性能排名**。
当前参数入口见 [LUT 参数选择](../../../primus_high_prec_lut/guides/performance/ntru-lut-presets.md)，历史计时不随现行源码更新。
数据截至 2026-10-13，来自同一台 Ryzen 9 9955HX3D、单线程在线请求；CPU4。
GLWE CBS 的 q1024/MSB、ordinary/split 新比较见[本批元数据](data/bootstrap-cbs-extension.json)；
GLWE PBS 与 EBS8 Low/High 见[对应元数据](data/bootstrap-pbs-ebs-extension.json)。其他组保留历史数据，源码版本和测量条件见[基线元数据](data/bootstrap-comparison-baseline.json)。适配器、补丁、fixture 和完整诊断材料不随仓库提交，也不保证另有本地归档；
本页与 CSV 可用于比较和复核统计，但不足以独立重建旧二进制。当前基准已精简验证流程，不能当作历史源码快照。

本页 Primus **GLWE Fourier** 数据早于精确系数建钥修复，使用了旧的未约简频域建钥表示；不能作为修复后基线或参数/安全认证。历史排名保留原值，当前修复成本见[独立测量](fourier-glwe-keygen.md)。此限制不自动适用于外部库或 NTT/NTRU 数据。

| 想比较的算法／请求 | 阅读位置 | 配对程度 |
| --- | --- | --- |
| GLWE：BR＋trace＋scheme switch CBS | [G1 NTT、G2 Fourier](#glwe-trace-cbs) | 模数、消息中心和分解层数/基数匹配；采样、trace、SS 或 KS 仍不同，属于派生协议 |
| GLWE：BR＋private/packing KS CBS | [普通与多值变体](#glwe-private-ks-cbs) | 原库参数参考，尚无 Primus 同路径配对 |
| NTRU：BR＋reverse trace＋scheme switch CBS | [NTRU 原语](#ntru-primitives) | Primus 自身 Low/High；没有外部 NTRU 同算法实测 |
| 普通 PBS，4→4 位返回 | [GLWE 三轮配对](#glwe-pbs)、[历史 NTRU 参考](#historical-pbs) | 当前 GLWE 匹配主要参数，NTT 单列 Q50 派生；旧 NTRU 单轮不混入 |
| EBS，8→4 位返回 | [LY23 与 one-hot LUT](#ebs8) | 同函数、相近 BR/KS 参数；算法及输入协议不同 |
| one-hot 高精度 LUT | [历史范围](#wide-lut)、[当前参数](../../../primus_high_prec_lut/guides/performance/ntru-lut-presets.md) | 外部同规模结果缺失；旧 Low/High 时间不代表现行预设 |


除明确标为“历史单轮”的表外，时间为**三个进程均值的平均 [最小，最大进程均值]**，单位 ms；
范围不是置信区间。保留离群值，CBS 主表统一展示 bit=1，终点为可消费的变换域 GSW，
不含后续外积/CMux 或解密；另标 CBS＋CMux 的新列包含实际消费。PBS/EBS 则包含必要的返回 KS。准备密钥、公开 LUT、输入加密均不计时。
历史组的全部 bit、core、prepared 消费及未四舍五入数据在[汇总 CSV](data/bootstrap-comparison-summary.csv)；
新 PBS/EBS 组的[原始样本](data/bootstrap-pbs-ebs-extension-samples.csv)及逐进程统计见本批元数据。

下文 `(L,b)` 均为 `(层数, log₂B)`；Q54/Q50 不是截断字宽，而是指定素数模数。
相同层数不保证相同 gadget 权重或可用精度。跨库表可比较这些具体配置的实际成本，
尚不能据此声称同安全强度或同完整请求失败率的加速比。

<a id="glwe-trace-cbs"></a>
## GLWE：BR、trace 与 scheme switch CBS

LightFHE、refined 和 Primus GLWE 都属于这一算法家族；其中 k=1 即 rank-1 RLWE。
流程是 BR 产生 gadget 尺度的环密文，trace 投影，再 scheme switch 生成完整 GGSW。

2026-10-13 新批次，CPU4、单线程、三轮交错共27个进程；[原始样本](data/bootstrap-cbs-extension-samples.csv)和[参数、产物哈希、逐进程统计与资源](data/bootstrap-cbs-extension.json)。
Primus 直接计时所属后端的正式 `cbs_identity`，库算法为 `5fc1a932`，本批源码只改基准注释。
G1 采用 q1024/MSB；G2 采用 MSB，ordinary/split35 分开，后者的分解参数对应 refined CMUX3。
“CMUX2/3”是作者的**参数组名称**，不是计时内 CMux 的次数；Primus 保留原 `CMUX2.../split35` ID。

| 组 | 代码库@版本／引擎 | 完整 CBS bit1→GSW (ms) | 完整 CBS＋CMux (ms) | 输入 KS |
| --- | --- | ---: | ---: | --- |
| G1 | LightFHE@7681a6ac 原版 | 82.087 [82.043, 82.110] | —（未测） | 无 |
| G1 | LightFHE@7681a6ac corrected | 81.127 [81.065, 81.162] | —（未测） | 无 |
| G1 | Primus@5fc1a932 NTT | 13.124 [13.034, 13.211] | 13.139 [13.086, 13.191] | 无 |
| G2 ordinary | refined@9b0426e8 CMUX2 | 8.734 [8.693, 8.812] | 8.715 [8.653, 8.765] | scalar |
| G2 ordinary | Primus@5fc1a932 RustFFT | 10.483 [10.402, 10.530] | 10.488 [10.422, 10.544] | ring |
| G2 ordinary | Primus@5fc1a932 TFHE-FFT | 8.029 [8.019, 8.039] | 8.188 [8.032, 8.498] | ring |
| G2 split35 | refined@9b0426e8 CMUX3 | 9.147 [9.100, 9.235] | 9.217 [9.122, 9.275] | scalar |
| G2 split35 | Primus@5fc1a932 RustFFT | 10.823 [10.809, 10.850] | 10.841 [10.819, 10.875] | ring |
| G2 split35 | Primus@5fc1a932 TFHE-FFT | 8.379 [8.359, 8.399] | 8.401 [8.394, 8.411] | ring |

这次 G1/G2 的输入模数和消息中心已经匹配，但跨库仍属于 **derived（派生协议）**：采样、trace、SS 或输入 KS 有差异，不能称为同协议算法加速。
Primus 内部 ordinary/split35 是只改变 trace 表示的参数对照；跨进程 FFT plan 和实际密文位模式仍可能不同。
此前 padded、Q54 大模数输入的旧时间留在[历史汇总](data/bootstrap-comparison-summary.csv)，不替换原始数据，也不将新旧差值称为内核加速。

所有新计时进程通过真实 t8、深度1消费检查；外部三把 key seeds42/43/44、每把四个输入的全部 mask/body 行均有诊断。
Primus 本轮先检查两 bit，计时后检查实际输出；历史全行/多密钥诊断的局限见[消费边界](#消费边界)。
外部 refined 本批还直接测量 CBS＋CMux；LightFHE 未测该组合，保持空白。独立采样会出现组合均值略低于 CBS，不能相减得到 CMux 耗时。

Primus Criterion Flat：20样本、0.5s预热、1.5s目标；外部每样本一次调用、30样本、1s预热。
三个轮次正序、逆序、G2先行；无构建并行，未剔除慢轮。Primus 使用 Rust1.98.1/LLVM22、默认features并启用 `tfhe-fft`；
refined 使用 nightly-2025-01-01/LLVM19、monothread＋nightly-avx512、TFHE0.5.4/concrete-fft0.4.1及已记录的依赖兼容补丁；LightFHE 为 GCC15.2 Release/native，无 HEXL。
双方 Rust 均 target-cpu=native；只固定CPU4，未隔离SMT sibling20或后台负载。没有新热路径变更，因此不重复 CPU8；不据此外推CPU8。

完整 CBS 在本矩阵中：Primus NTT 比 LightFHE 快；G2 的 Primus TFHE-FFT 比 refined 快，RustFFT 比 refined 慢。
这包含密钥结构、KS、变换、编译器及内部分配的共同效果，没有隔离单个算法贡献。
TFHE-FFT ordinary 的 CBS＋CMux 三轮为 **8.032、8.498、8.035 ms**，中间慢轮完整保留；其平均值不能用于宣称 split 仅增加某个稳定百分比。
Split 增加表示成本，在 G2 这些固定消费者上没有新增必要性，普通 trace 仍为默认。A3的精度诊断见[消费边界](#消费边界)，不能冒充作者 CMUX3 的同协议结果。

### G1：NTT 参数差异

| 参数/流程 | LightFHE NTT | Primus NTT 派生组 |
| --- | --- | --- |
| n / k / N | 571 / 1 / 2048 | 相同 |
| 环 Q | 18014398509404161 | 相同 Q54，无 Q50 替换 |
| BR / Trace / SS / 输出 | (2,17) / (3,13) / (2,19) / (4,4) | 相同层数和 base log |
| 输入 | q1024、p2，bit 相位 0/512 | 相同 q1024/MSB 中心；居中 LUT 保护区间不同 |
| 输入/行噪声 | 声明 σ3.2；原版支持 ±4，corrected 支持 ±39 | 输入和环行 σ3.2（CDT，支持 ±38） |
| BR / Trace / SS | 外积后差分；/N 后 forward trace；RLWE[s²] SS | 差分后外积；逐层归一化 reverse trace；GGSW[−s] SS |

两边均为独立 dense binary 小/环秘密。Primus 完整 bundle 另含辅助返回 ring KS(6,8)、行σ3.2，本次直接 CBS 不调用它。作者的奇数 gadget 权重、实际 LUT 幅度
2floor(g/2)、centered-Q digits 与 Primus 二进制权重及 carry 不完全相同。
LightFHE 原版与 corrected-sampler 分开记录，后者只修改 Gaussian 截断表达式，但改变
采样分布及 RNG 消耗。C++17 signed-left-shift 的未定义行为限制仍在；本结果仅描述
GCC 15.2 当前优化产物，不证明跨编译器正确。

### G2：Fourier 参数差异

| 参数/流程 | refined Fourier | Primus Fourier 派生组 |
| --- | --- | --- |
| 小/外部 n / k / N / Q | 636 / 2048 / 1 / 2048 / native64 | 相同 |
| BR / Trace / SS / 输出 / 输入 KS | (2,15) / (6,7) / (2,17) / (4,4) / (5,2) | 相同层数和 base log |
| 输入编码 | MSB，0/2⁶³；LUT 对称保护半径 N/4 | 相同 MSB 中心；居中 LUT 保护半径 N/2，严格端点不含 |
| 新鲜大输入与环行 σ | βQ=17065.45141033878 | 相同声明系数单位，采样分布不同 |
| 输入 KS 行 σ | αQ=1706545141033878 | 相同声明系数单位，采样分布不同 |
| 小/环秘密 | 独立 dense binary | 相同分布类别 |
| CMUX2 / CMUX3 trace 表示 | ordinary / unsigned low35＋high29 | ordinary / Split35，只改变 trace |
| 输入准备 | scalar LWE KS | inverse extraction → Fourier ring KS → compact extraction |
| Trace / SS 输出 | 先 /N 再 forward trace；mask 回 coefficient 后统一转 Fourier | 逐层 reverse trace；保留 mask Fourier accumulator |

refined 为 rounded continuous Gaussian，Primus 为截断 discrete Gaussian；digit 中点
carry 和 FFT 舍入路径也不同。完整请求的差距不能全部归因于 CBS core，尤其两种 KS
并非同一密钥的存储重排。未建立共同安全性、DFR 或深层 CMux 预算。

### G1/G2：资源与参数选择

单位 MiB/KiB 均为二进制单位。外部列 source-derived **ciphertext payload**，Primus 列相同库源码的 MSB 验收中实测 **client＋完整 server retained requested heap**；两列口径不同，不求其比值。
Evaluator heap 含 CBS 程序，不含借用 context/key、调用方输入/输出；外部完整 workspace 未测，留空。

| 配置 | 外部 key payload (MiB) | Primus key pair heap (MiB) | evaluator heap (KiB) | 本批进程峰值 RSS (MiB) |
| --- | ---: | ---: | ---: | ---: |
| G1 / LightFHE original | 72.469 | — | — | 274.23–274.36 |
| G1 / LightFHE corrected | 72.469 | — | — | 274.31–274.55 |
| G1 / Primus | — | 72.908 | 420.125 | 86.34–86.54 |
| G2 ordinary / refined | 131.453 | — | — | 163.71–163.98 |
| G2 ordinary / Primus RustFFT | — | 82.120 | 555.102 | 96.64–96.78 |
| G2 ordinary / Primus TFHE-FFT | — | 82.120 | 555.102 | 97.41–97.50 |
| G2 split35 / refined | 133.516 | — | — | 163.87–163.97 |
| G2 split35 / Primus RustFFT | — | 84.007 | 603.102 | 99.21–99.29 |
| G2 split35 / Primus TFHE-FFT | — | 84.006 | 603.102 | 99.58–99.77 |

G2 作者 scalar KSK payload=52,183,040 B，Primus ring KSK=163,840 B，不能视为同一密钥的紧凑表示。
Split trace payload 从2,162,688增至4,325,376 B；Primus evaluator增加48 KiB。RSS包含构建密钥、诊断及 Criterion 过滤之外的其他 case setup，
不是纯服务峰值；外部建钥临时标准域材料也可能推高 RSS。Primus 的在线零分配由相同生产源码的既有探针确认，本批计时没有加入 allocator 插桩。

| 候选或缺口 | 当前选择与边界 |
| --- | --- |
| G1 q1024/MSB、G2 MSB ordinary | 保留正式操作入口和现有 bench；这批配置仍为 experimental，不转成正式安全参数 |
| G2 Split35／CMUX3 gadget 组 | 保留显式精度选择；不替换 ordinary 默认值，仍需为具体后续消费者核算误差 |
| scalar 输入 KS | 本地G2对照的完整CBS＋CMux在CPU4/8慢约21%～23%/11%～14%；KSK payload大318.5倍，仅少98KiB scratch。顶层保留ring KS，低层scalar能力保留 |
| rank1 轻量 SS | 完整收益不一致；一份key＋workspace净省14KiB（NTT）/30KiB（Fourier），两个workspace反而多36/4KiB。保留通用SS；CPU8/TFHE-FFT正向结果仅作指定用途复测线索 |
| Fourier CMUX1、LightFHE CMUX3 | 已有真实消费失败；本表没有时间，不能借用其他参数组 |
| private/packing CBS、block/subset 秘密协议 | 仅列外部功能参考，Primus 尚无同协议配对 |
| 外部 NTRU CBS、16/20/24位高精度 LUT | 没有可运行且通过同用途验证的配对，保持空缺 |

scalar KS与轻量SS的取舍来自同日 `5fc1a932` 的本地配对实验，原始材料未纳入公开数据包，也不作为上表的跨库计时。只有新参数、互操作需求或明确部署用途改变成本判断时才值得重开。

参数入库仍需安全模型与秘密/采样条件、完整误差传播和请求级失败预算；预算保持可配置，不从有限样本推算极低DFR。
正式选择须以具体用途（输出层数、消费深度、是否返回LWE）为单位；本轮不因某项时间更短降低分解或噪声。

**同家族、未配对的 TFHEpp annihilate 参考：**它也使用 trace/SS，但 BR 环、秘密、输出 gadget 和输入 KS
不同，不能并入 G1/G2 当作匹配参数。外部输入均为 n1024/native32，内部小 LWE n630/native16；
AH/SS=(5,9)，环行 σ=8192，环秘密 ternary，输入 KS 使用共享秘密前缀的 subset KS。

| 实现 | 小秘密 | BR 环与输出 `(N,k,Q)` | BR＝输出 `(L,b)` | 输入 KS | 完整 CBS (ms) |
| --- | --- | --- | --- | --- | ---: |
| TFHEpp block annihilate | block binary，ell=2 | (1024,2,2^64) | (4,10) | (5,2)，subset | 9.349 [9.259, 9.487] |
| TFHEpp dense annihilate | iid binary | (2048,1,2^64) | (4,9) | (7,2)，subset | 16.172 [16.063, 16.371] |

G1/G2 与 TFHEpp 均验证了 t8、深度 1 的真实消费；TFHEpp 低层 residual 超过 gadget 权重，
不能把名义位数当作全部可用精度。这些历史参考只确认 t8、深度 1 的消费范围。

<a id="glwe-private-ks-cbs"></a>
## GLWE：BR 与 private/packing KS CBS

此类使用函数／packing key switch 构造 GGSW 行，区别于上一类的 trace/SS。
TFHEpp 普通 CBS 在本表相同 mask/body 分解时一次 ManyLUT BR；MOSFHET ordinary 每输出层一次 BR，
multi_value 共享多槽 BR，ring_private 进一步用环函数密钥生成 mask 行。
Primus 当前比较路径不是这个构造，因此本表只列外部算法参考；相近 N 仍不足以当作 Primus 配对结果。

| 实现 | BR `(N,k,Q)` / `(L,b)` | 输出 `(N,k,Q)` / `(L,b)` | 在线输入 KS | 完整 CBS (ms) |
| --- | --- | --- | --- | ---: |
| TFHEpp block ordinary | (1024,2,2^64) / (4,10) | (1024,1,2^32) / (4,6) | (5,2) scalar | 43.040 [41.881, 43.743] |
| TFHEpp dense ordinary | (2048,1,2^64) / (4,9) | (1024,1,2^32) / (3,6) | (7,2) scalar | 42.324 [40.695, 44.922] |
| MOSFHET ordinary | (2048,1,2^64) / (4,9) | 同 BR | 无 | 207.138 [206.461, 207.554] |
| MOSFHET multi_value | 同上 | 同上 | 无 | 153.849 [153.539, 154.222] |
| MOSFHET ring_private | 同上 | 同上 | 无 | 81.010 [80.424, 81.929] |

TFHEpp 的小/外部 LWE 尺寸及秘密同上面的 annihilate 表，普通入口使用独立输入秘密、
完整 scalar KS，private KS=(8,3)，输出环 σ≈147.033（block）或 128（dense）。
MOSFHET 输入 n632/native64、dense binary、σ=2^49；环秘密 dense binary、σ=2^20；
private/body packing KS=(8,4)，ring_private 两把环函数密钥=(10,4)。其 unsigned digit 预乘密钥与
TFHEpp signed gadget 不同；这些数值差异未在本轮消除。

TFHEpp ordinary 的 private KS payload 约 1 GiB；MOSFHET ordinary/multi_value 的 private＋packing
KS 约 7.51 GiB。在线展开、分配保留在计时内。全部只验证 t8、深度 1 消费，名义输出位数未全部证明可用。

<a id="ntru-primitives"></a>
## NTRU：未配对的历史自身基线

没有可运行、通过同用途验证的外部 NTRU CBS 配对；本页不再把 Primus
自身旧 Low/High 参数表列成另一组跨库结果。该未配对的旧样本已退休，
需要追溯时从 Git 恢复，不继续作为当前报告的证据集维护。
它们早于投影融合、split FFT 和逐 c/o 参数；不能对应当前 DFR30/DFR128 名称。
GLWE GGSW 和 NTRU NGSW 的行数、秘密、尺度及误差传播不同，也不能只按 N 比较。

<a id="glwe-pbs"></a>
## 普通 GLWE PBS：4→4 位完整返回

本批源码为 Primus `354d1db8` 加本次基准变更（库源码未变），外部为 TFHE-rs artifact `e1f5d362`。
共同使用 u64、n1024/精确 binary h128、k1/N4096/独立 dense binary 环秘密、classic BR→KS，
同函数 `((13*m) XOR (m>>2))&15`，固定计时输入13→输出10。Low/High 是分解组标签。

| 实现 | Low 完整返回 (ms) | High 完整返回 (ms) |
| --- | ---: | ---: |
| TFHE-rs artifact／GLWE Fourier | 44.957 [44.593, 45.425] | 87.223 [85.303, 89.863] |
| Primus GLWE NTT／Q50 派生 | 65.949 [64.408, 66.748] | 136.248 [133.697, 137.740] |
| Primus GLWE RustFFT | 65.805 [65.645, 66.046] | 129.934 [124.955, 132.754] |
| Primus GLWE TFHE-FFT | 52.864 [52.733, 53.047] | 103.859 [98.491, 107.146] |

| 参数/路径 | 外部 TFHE-rs / Primus Fourier | Primus NTT 派生 |
| --- | --- | --- |
| 输入/环/返回模数 | native64 | Q50=1125899906826241 |
| 消息域 | padded4，Δ=2^59；Primus t32 | t32 Rounded |
| 输入、KS 行 σ | 系数 3.2×2^40 | 系数 3.2×Q50/2^24 |
| BSK/环行 σ | 系数 1.5 | 系数 1.5，归一化噪声不同 |
| Low BR / KS | (4,10) / (6,3) | 同 L,b；绝对权重不同 |
| High BR / KS | (9,5) / (9,2) | 同 L,b；绝对权重不同 |
| 返回 | 外部：提取→scalar KS；Primus：ring KS→compact extraction | Primus ring KS→compact extraction |

全 16 个输入均验证实际返回秘密和完整 phase 距离，包含 padding 半区。采样器、返回算法、变换及工具链不同；
这里的 Fourier 配对比 NTT 派生更接近，但仍不是同安全性/DFR 证明。
外部在本批两组完整请求均更快；尚未分离 BR、KS、分解或 FFT 的贡献，不据此调整生产默认值。

<a id="historical-pbs"></a>
## 普通 PBS：历史单轮参考的限制

2026-10-11 的单轮适配器还比较过 TFHE-rs artifact 与 Primus NTRU PBS/CBS。
该单轮样本及旧 EBS8 样本已由后面的多轮同用途比较取代，从 Git 追溯，
不继续与后来的三轮结果并列维护。
该批输出验证弱于后续全行/真实消费诊断，且 GLWE private-packing CBS 和
NTRU trace/SS CBS 是不同算法，故不再保留重复排名表或等价加速比。

<a id="ebs8"></a>
## EBS：相同 8→4 位函数的完整返回

现行 one-hot LUT 基准入口见独立仓库的 [lookup_ebs8](../../../primus_high_prec_lut/benches/lookup_ebs8.rs)；
下表保留原版本和参数，不用当前基准结果替换历史值。

函数 `F(x)=((13*x) XOR (x>>2))&15`，x=0..255，输出一个外部 LWE，含全部返回 KS。
函数有 64 的周期，但双方均执行约定完整表/路径，没有利用周期缩小定义域或跳过计算。
参数和范围固定如下，没有调整噪声、η、保护间隔、分解或 scratch 查询。

| 条件 | LY23 Low / High | Primus NTRU Low / High |
| --- | --- | --- |
| 外部秘密 | n1024、固定重量 binary h128 | 相同尺寸/重量，独立 RNG/采样器 |
| 输入 | 单个 native64 LWE，padded 8-bit，Δ=2^55 | 两个 q52/t32 LWE，低 chunk 在前 |
| 返回 | native64 LWE，padded 4-bit，Δ=2^59 | 一个 q52/t32 LWE，Δ=2^47 |
| 环 | GLWE k1/N4096/native64，dense binary secret，σ=1.5 | NTRU N4096，NTT Q50/σ_f,g=1 或 Fourier native64/σ_f,g=1.5 |
| 输入/KS 噪声 | normalized 3.2·2^-24 | coefficient 3.2·2^28，对 q52 归一化相同 |
| BR / KS | Low (4,10)/(6,3)；High (9,5)/(9,2) | 相同 L,b，模数及权重不同 |
| 其他操作 | η4、每函数值重复 W64；串行 4096 次 GGSW 外积 | M16/c2/d2/o1，两个 one-hot CBS、聚合/旋转、initializer lift，无高 chunk 选表树 |
| Trace / SS / selector | 不执行 | Low (6,7)/(6,8)/(2,10)；High (15,3)/(6,8)/(1,17) |

本节与上面的 GLWE PBS 来自同一新批次，固定输入171→输出5。

| 实现 | Low 完整返回 (ms) | High 完整返回 (ms) |
| --- | ---: | ---: |
| TFHE-rs artifact／LY23（GLWE） | 142.050 [141.739, 142.452] | 284.949 [281.195, 287.824] |
| Primus NTRU NTT／one-hot LUT | 75.301 [75.084, 75.498] | 129.758 [128.911, 130.414] |
| Primus NTRU TFHE-FFT／one-hot LUT | 60.077 [59.936, 60.347] | 101.447 [100.031, 102.496] |

本机实际成本差异可以从这些完整请求观察，但**不能把表中比值解释为同安全性/DFR 的算法加速比**。
Primus 两种环模数/采样宽度也不同，不将 NTT 与 Fourier 的差距归因于单一变换 kernel。

LY23 是 GLWE 扩展 accumulator 的串行 EBS；Primus 是 NTRU one-hot CBS 聚合控制后的 LUT。
本次 c=d=2 没有高 chunk 选表树，不能代表下面 c>d 的高精度请求。
本批 High 首次接入时，Primus 两后端和外部均通过独立的 256 输入全域诊断；外部 Low 也做了全域诊断。
正式计时进程保留 8 个代表输入检查，并重置独立输入 RNG 生成测量密文。均为 key seed42 的有限检查，
完整 phase 距离包含 padding；没有用成功样本推导 DFR。旧 EBS8 批次保留在历史 CSV，不与本批合并。

### 本批存储与测量口径

纯密文 key payload（MiB）：外部 GLWE BSK＋scalar KSK 为 Low 704.188 / High 1440.281；
Primus GLWE BSK＋ring KSK 为 512.375 / 1152.563；Primus NTRU BSK＋返回 KSK＋trace＋SS 为 322.625 / 582.094。
BSK 在 GLWE 中有 `(k+1)^2` 行因子；两种 KS 的存储差异属于算法差异。

按构造器元素长度计算，Primus GLWE evaluator 缓冲为 456 KiB；NTRU NTT Low/High 为 2.535/2.129 MiB，
NTRU Fourier 为 2.910/2.473 MiB。这里包括 evaluator 持有的 one-hot LUT/旋转常量，
不含借用密钥、context 变换表、输入输出、独立公开 LUT、容器/对齐开销；Fourier 还未计 FFT engine 缓冲，
因此不是完整堆内存测量。外部 scratch API 请求 PBS 368767 bytes、EBS 2662527 bytes，口径同样不含整个请求状态。
精确公式和逐进程峰值见本批元数据。

| 完整进程（包含建钥） | Low 峰值 RSS 范围 (MiB) | High 峰值 RSS 范围 (MiB) |
| --- | ---: | ---: |
| 外部 GLWE PBS | 1028.6–1029.0 | 2308.9–2309.0 |
| Primus GLWE NTT PBS | 524.6–527.1 | 1164.7–1167.4 |
| Primus GLWE RustFFT PBS | 525.1–528.0 | 1165.6–1168.0 |
| Primus GLWE TFHE-FFT PBS | 525.5–529.0 | 1165.9–1169.1 |
| 外部 LY23 EBS | 1028.9–1029.1 | 2309.0–2309.0 |
| Primus NTRU NTT EBS | 336.9–339.8 | 595.9–599.1 |
| Primus NTRU TFHE-FFT EBS | 338.9–342.2 | 598.2–601.2 |

峰值由 `/usr/bin/time -v` 测得，外部建钥时曾同时持有标准域和 Fourier BSK；不能将进程 RSS 当作在线 workspace。
每组 3 次交错独立进程、每进程 30 样本，中轮逆序；CPU4、OMP/Rayon=1，不与构建并行。
Primus 用 Criterion Flat（预热1秒、目标3秒），外部用 Instant（预热3次、逐次调用），每次迭代均为一个完整请求。
Primus Rust 1.98.1/LLVM22，外部 nightly-2025-01-01/LLVM19，后者启用 nightly-avx512 和本地 pulp 兼容补丁；
双方 target-cpu=native。仅固定 CPU，没有隔离 SMT sibling20 或后台负载，范围反映实际进程波动。

<a id="wide-lut"></a>
## One-hot 高精度 LUT：历史范围

旧 M16/d3/c4～6/o4 的 Low/High 参数和测量已由当前逐 c/o 参数报告取代，
旧样本仅从 Git 追溯。没有外部同规模、同输入协议的正式结果；8→4 位 EBS 不能补入这个空缺。
现行 28 组逐 c/o/DFR 参数、选取依据和数值限制集中在 [LUT 参数报告](../../../primus_high_prec_lut/guides/performance/ntru-lut-presets.md)。

<a id="lut-stages"></a>
旧 `prepare_controls`/`lookup_prepared` 是已撤回入口，当前不能运行这些命令。
二者独立采样改变缓存状态，不能相加替代完整 evaluate；旧阶段均值不再重复列出。
当前普通公开基准只测完整请求或独立算子，不提供测量专用阶段 API。

## 消费边界

匹配参数和成功PBS不证明任意CBS输出可用。历史多密钥诊断中，
TFHE-FFT ordinary/padded/seed104的GGSW行超过当时g/16诊断线；
q1024/native的A3 ordinary也有行超界，Split35固定样本通过。
CMUX1在两种编码/trace表示下均出现真实消费失败。
这些反例仅说明参数/精度预算须覆盖后续消费，不能当作所有ordinary路径有错。
内部q/Q、padded/MSB验收矩阵及旧回归时间已退休，当前契约见
[域与返回](../development/bootstrapping-contracts.md#ciphertext-domains-and-return)、
[CBS消费](../development/bootstrapping-contracts.md#ordinary-cbs-and-consumption)。

## 如何使用这些结果

优先使用 G1/G2 的跨库近参数对照；其他表按算法、输入协议和输出目的分别阅读。
原库配置名中的安全位数不能转移到派生参数，有限全域/多密钥验证不代替完整请求 DFR。
GLWE CMUX2/CMUX3 是后端比较配置，当前 NTRU 逐 c/o/DFR 预设也仍为实验参数；
尚未建立统一安全性、完整请求失败率和后续多层消费预算，不能升级为正式参数。

历史跨库表使用CPU4。并行的正确性进程未混入计时。
历史分派证据中，Primus NTT Q54 使用 DQ、Q50 使用 IFMA；TFHE-FFT 是浮点 AVX-512，不是整数 IFMA。
新 PBS/EBS 批次未重新采集分派栈，不以存在某个机器指令替代实际调用证据。
工具链、FFT plan 与采样 harness 也不同；这些因素尚未被独立控制。

## 原始数据与来源

保留的原始样本保持原格式，`iterations` 列存在时先将总时间除以迭代数，不能把一次 Criterion sample 当作一次请求。
统一汇总按 case/workload 先算各进程均值再取三进程平均；中位数来自合并后的每请求样本，范围来自三个进程均值。

| 组 | 原始数据 |
| --- | --- |
| 2026-10-13 GLWE MSB CBS／CMUX2、CMUX3 | [逐样本时间](data/bootstrap-cbs-extension-samples.csv)、[版本/参数/资源/逐进程统计](data/bootstrap-cbs-extension.json) |
| TFHEpp | [逐次调用](data/tfhepp-cbs-samples.csv) |
| MOSFHET | [逐次调用](data/mosfhet-cbs-samples.csv) |
| 2026-10-13 GLWE PBS / EBS8 Low、High | [逐样本时间](data/bootstrap-pbs-ebs-extension-samples.csv)、[参数/哈希/逐进程统计](data/bootstrap-pbs-ebs-extension.json) |

历史组固定上游版本如下；测量还使用了适配器、依赖锁和兼容补丁，因此单独 checkout 这些版本不等于复现旧测量。

| 代码库 | 固定 commit |
| --- | --- |
| [primus](https://github.com/haofeiliang/primus-fhe) | `3ab35a14474f89bcc2289a062c21245360482a42` |
| [lightfhe-ntt](https://github.com/LightFHE/NTT-based-circuit-bootstrapping) | `7681a6ac1eafe864c17e4e9a79cde51f337b6aa6` |
| [refined-cbs](https://github.com/KAIST-CryptLab/refined-tfhe-lhe) | `9b0426e8e197020a4bf40776cc03641e6cf9b90e` |
| [tfhe-rs-artifact](https://github.com/zama-ai/tfhe-rs) | `e1f5d36224ca88991b49e38fa6791ab18a9f63d1` |
| [tfhepp](https://github.com/virtualsecureplatform/TFHEpp) | `2d2cf7cdc2d6a9181ceb90803038dad43b6ea5d6` |
| [mosfhet](https://github.com/antoniocgj/MOSFHET) | `a6e7fbb47cd4451ebcc6693027e65a27d934a399` |
