# Fourier GLWE 精确建钥：成本与使用边界

2026-10-26，`f65199cc`（旧错误表示）→ `5b005d2e`（精确系数建钥）。参数不变，比较两个 FFT 引擎及 CPU4/CPU8。**修复应保留；旧路径不能因建钥更快而恢复。**

## 表示与适用范围

普通加密、GLev/GGSW、classic/sparse BSK、ring/packing KSK、AK/trace 和 SSK 都先完成 native 系数行及 gadget 对角项，再转换。Split35 trace 复用同一精确准备；online 表示不变。低层接口及旧材料更换要求见 [GLWE 加密契约](../../crates/primus_glwe/README.zh_CN.md#加密与解密)。

精确系数乘积不等于无损 Fourier 表示。ordinary u64 的浮点转换误差仍影响最终相位；Split35 仅用于当前支持的 trace，不自动修复 BR/SS 精度。既有小参数 oracle 覆盖 native 行和公开频谱；本页的实际参数完整工作流检查只是有限样本，不证明安全成本或 DFR。

## 参数与测量口径

所有卡 GLWE rank=1、Q=native；分解写作 `base_log/L`。数值来源为上述版本的 `experimental.rs` 与元数据列出的四个 benchmark。未改参数搜索、FFT 自动规划或在线内核。

| 卡 | w；n/N | 小秘密/环秘密 | BR | KS | trace；SS；CBS输出 |
| --- | --- | --- | --- | --- | --- |
| F-D32 | 32；866/2048 | binary/binary | 8/3 | 2/13 | — |
| F-D64 | 64；866/2048 | binary/binary | 23/1 | 3/5 | — |
| F-F64 | 64；728/1024 | H32/iid ternary | 8/8 | 8/8 | — |
| F-C64 | 64；800/1024 | binary/均匀ternary | 8/8 | 8/8 | 8/8；8/8；8/2 |
| F-G1 | 64；571/2048 | binary/binary | 17/2 | 8/6 | — |
| F-G2 | 64；636/2048 | binary/binary | 15/2 | 2/5 | 7/6；17/2；4/4 |

F-G1分别用q=Q与q1024；它的split指q/Q分离。F-C64/G2的Split35指trace精度。BK=BR→KS，KB=KS→BR；外部输入域随order变化。F-F64仅切换classic/sparse(r3/B64)。F-C64计CBS→CMux→LWE返回；G2计identity CBS和CBS+CMux，不含额外LWE返回。

- Ryzen9 9955HX3D，Rust1.98.1/LLVM22.1.8，`target-cpu=native`，RustFFT、TFHE-FFT、split-trace；未启用nightly SIMD。辅助NTT仍有自己的运行时SIMD分派。CPU4/8是同一设备96/32 MiB的两个L3组，逐进程绑核串行测试。
- 每项先校验后计时。Criterion每次迭代一个完整请求，20样本、0.5秒预热、2秒目标测量；setup、输入准备和分配在外。建钥与context/FFT规划分别计时。
- 建钥中位数来自3次独立进程（复测项5次），含客户端采样、准备、分配、行生成和临时drop，排除context、RNG构造、最终密钥drop。
- 在线60组配对中，初始异常项目交替复测两次后取三个进程均值的中位数；其余为单进程均值。[CSV](data/fourier-glwe-keygen-2026-10-26.csv)保留样本数、范围及中位数对应进程的CI，不能视为跨进程联合CI。

## 结果与选择

建钥耗时增至旧版约 **1.48–1.89倍**，增量主要来自每行精确乘积、CRT恢复和最终规范化转换；辅助表/秘密准备很小。在线配对变化为 **−1.33%～+2.27%**，中位数约−0.03%，不是优化收益承诺。以下列出CPU4/TFHE-FFT代表项，全部两核/两引擎数据在CSV中，单位ms。

| 请求 | 总建钥 旧→新 | 完整在线 旧→新 |
| --- | ---: | ---: |
| F-D32 | 136.865 → 245.084 | 13.153 → 13.256 |
| F-D64-BK | 52.173 → 84.845 | 5.508 → 5.496 |
| F-F64-classic | 171.548 → 289.659 | 12.401 → 12.337 |
| F-F64-sparse | 555.206 → 849.663 | 15.690 → 15.595 |
| F-C64-ordinary | 192.624 → 320.945 | 13.737 → 13.728 |
| F-C64-split35 | 197.586 → 320.082 | 13.738 → 13.783 |
| F-G2-ordinary +CMux | 74.126 → 129.572 | 7.214 → 7.208 |
| F-G2-split35 +CMux | 75.900 → 130.321 | 7.549 → 7.559 |

CPU8/u32/TFHE-FFT原计时ELF的三次均值为旧13.120–13.137、新13.392–13.430 ms，中位数慢2.27%，保留该不利结果。另加plan日志重编译，两版均自动选择`(Dif4,1024)`，差距约0.5%。诊断不能追溯原进程的plan或替换原结果；代码布局/环境影响尚未完全定位，不宣称每个ELF零回退。

服务器key payload与在线workspace大小不变，104个独立allocation检查的在线请求均0次分配。建钥峰值请求heap差值约−68.9～+168.3 KiB；它不是RSS差值，且不包含allocator内部开销。原始RSS和分配计量分列在CSV。

修复后rank1的两prime秘密缓存16N bytes、乘积scratch16N、native行u64为16N/u32为8N；本机两张AVX512辅助NTT表另约100N bytes。u64/u32准备态合计约148N/140N，不含FFT工作区及小元数据。Split35生成另需16N临时缓冲。Z准备释放后才准备s_pad，没有全份系数BSK副本。

后续若优化建钥，应以精确版本为基线单独验证逐行算术；不恢复未约简频域私有乘积，也不因本次功能检查通过而调高参数的安全/DFR声明。

## 证据与复测

[元数据](data/fourier-glwe-keygen-2026-10-26.json)记录源码、工具链、features、ELF hash、临时选择器和统计口径；10个计时ELF曾从相同补丁重建并核对hash一致。这里保存紧凑历史证据，不分发临时driver、原始样本或二进制，也不承诺当前bench可逐位重建历史结果。

当前入口为[后端基准](../../crates/primus_tfhe_glwe_fourier/README.zh_CN.md#基准)。测量建钥应单列准备成本；在线按正常evaluator流程复用资源。更换参数、编译器或FFT规划后应重新验证。历史[跨库比较](bootstrap-functional-comparison.md)和[首项覆盖实验](fourier-first-write.md)中的Primus GLWE Fourier使用旧建钥表示，不作为本修复后的性能基线。
