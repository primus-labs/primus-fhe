# BFV HPSPOVERQLEVELED：完整请求与资源取舍

2026-11-05。该策略保持外部加密Q，在较小内部Q_l中计算并恢复Q；普通用户可用有限
`BfvLeveledParameters`，数学及使用前提见[工作基契约](../development/bfv-working-basis.md)。
默认仍Exact，原HPSPOVERQ自动P策略没有被隐式替换。

## 负载和比较条件

每个fresh请求包含两次完整slot编码、两次真实公钥加密、multiply/relin、square/relin、
rotation、Alice到Bob换钥、解密、slot解码、全部N槽核对/checksum及分配/析构。Context、
plan、普通keys和operation准备独立计时。Prepared请求复用全部输出与scratch，仍执行
同一条完整链，只把分配移到准备阶段。没有网络或SSLE协议工作。

外部参数为N16384/Q240、N32768/Q360，t65537、CBD1 secret/ephemeral、CBD21 error，
gamma=2^61−1；两个keybackend为full signed radix16和Native Hybrid alpha1。实际data Q
是工厂规定的4/6个60-bit primes，完整有序Q/P在数据中。Hybrid key P为
`[1152921504606584833]`；computation P独立记录，不把它算成key暴露模数。

同外部N/Q/t及错误分布，比较：原默认full-auto、相同P控制组full-controlled、显式固定
working basis，以及实际normal-plan。另给q360最短已认证P-prefix基线。普通plan两层的
working levels分别为q240的[2,2]和q360的[3,4]，P数量为[2,2]和[3,2]；外部始终level0。
Rotation/switch使用最后step的实际工作key，并另计其误差。

这里的同目标指同一确定性误差充分条件、相同外部加密参数和规定的bare-LWE参考筛查，
不是新的完整相关密钥安全等价定理。精确匹配的已知攻击输入缓存覆盖全部实际Q/QP
prefix；最低有限参考约160.6bits，10个routine无有限返回不等于无限安全。相关/循环
keys、结构化RLWE和多用户安全仍保留相应假设。

## 结果

以下主比较以**固定60-bit P池中满足同一完整两层电路充分条件的最短prefix**为full基线。
q240使用P3；q360也使用P3，后者专门追加了同一新二进制下的配对实验，避免把旧P4
过配控制组作为主结论。最短prefix不是所有prime大小、资源选择或证明方法下的全局最优。

| 外部profile | keybackend | full基线ms | normal-plan ms | 完整请求变化 | operation requested heap MiB | 整进程RSS中位MiB |
| --- | --- | ---: | ---: | ---: | --- | --- |
| N16384/Q240 | Radix16 | 24.386 | 13.575 | −44.34% | 15.894→22.445 | 78.521→53.643 |
| N16384/Q240 | Hybrid alpha1 | 20.869 | 12.987 | −37.77% | 20.348→26.383 | 53.441→49.912 |
| N32768/Q360 | Radix16 | 85.889 | 40.546 | −52.79% | 41.785→60.697 | 282.801→140.285 |
| N32768/Q360 | Hybrid alpha1 | 69.631 | 38.973 | −44.03% | 53.692→69.072 | 160.549→128.488 |

每个主比较格54个fresh请求，3个cycle方向一致。普通plan保留每层独立key和prepared
owner，q240相同level的两层也未特殊合并，因此operation scratch增加约29%～45%。
较小working keys降低了另一部分内存；requested owner heap、key heap与RSS各自列出，
不能用RSS下降冒充在线scratch下降。旧矩阵部分进程的RSS包含后置phase诊断；补充版本
另记录诊断前RSS，全部原样本和字段均保留。

原默认HPS自动P2的完整请求中位数也保留：q240 Radix/Hybrid为23.055/19.497ms，
q360为82.373/66.916ms。这些实际样本全部正确，但P2未通过本次完整最坏情况证书：
q240终端误差上界约为half-Delta的1.00049倍，q360约48.0127倍。它原本只为epsilon项
配置P，不承诺该深度的完整预算；不能把“未获该证书”改写成这些请求实际解密失败。
P3通过、P2拒绝的独立整数条件均留在证据中。

## 采样、正确性与可追溯性

主矩阵4策略×2尺寸×2keybackend，三轮ABCD/DCBA平衡顺序；q360补充P3基线与plan的
三轮ABBA/BAAB。共120个进程、1080个fresh完整请求及360个prepared完整零分配请求，
全部通过。保留全部样本/失败与最小最大值，不丢弃warmup、不挑选最快阶段拼接。

20个独立phase场景覆盖6个阶段，共3145728个系数检查。Oracle自行执行F_p negacyclic
NTT、automorphism、宽整数CRT和严格codec不等式；120个stage的原始整数误差也均小于
独立完整确定性界。普通工厂的64个depth/model请求另与独立forward搜索核对：38接受、
26超深拒绝，所有schedule/P/E一致。

一台AMD Ryzen9 9955HX3D工作机，单worker，stable1.98.1 release，系统allocator附原子
分配计数；设置RAYON_NUM_THREADS=1。可选portable SIMD关闭，NTT仍可运行时使用CPU
intrinsics。编译flags、CPU、实际key/P、setup、owner/RSS、两个源/二进制身份及所有
时序保留。该结果不承诺跨机器的同幅收益，也不是SEAL/OpenFHE或完整SSLE速度对照。

[压缩证据](data/bfv-working-basis-2026-11-05.json.gz)包括源文本、锁文件、正常依赖构建、
全部时间/资源样本、数学/phase汇总与最终检查；不包含运行秘密、原始phase数组或ELF。
可以审计和重建数值负载，不保证不同编译器/CPU自动重放相同计时。

维护中的Criterion入口是`cargo bench -p primus_bfv --bench working_basis`，比较原默认
full HPS与实际工厂plan的一条prepared fresh coefficient请求；其负载比上表少rotation/
switch及slot编码。`-- --test`仅作完整调用smoke，不能把该耗时当作统计延迟。
