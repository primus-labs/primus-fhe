# 普通 BFV/BGV 参数、预算与安全参考

普通调用分为三个结果：生成数值配置、准入所声明的电路、单独评估安全条件。
`create_context()` 负责第一项；BFV 的 `BfvLeveledParameters::try_new` 和 BGV 的
`BgvCircuitPlan::try_new` 负责第二项。两者均不返回“安全128位”的认证。
完整用法见 [BFV working_basis](../../crates/primus_bfv/examples/working_basis.rs)
及 [BGV leveled_coefficients](../../crates/primus_bgv/examples/leveled_coefficients.rs)。

## 选择配置和电路

| 条件 | BFV | BGV |
| --- | --- | --- |
| 数值请求 | `BfvLeveledRequest` | `BgvParameterRequest` |
| 明文 | 系数模数 t；可要求全环 batching | 系数模数 p；合数也可用于系数运算 |
| 资源 | 显式 N、Q prime 位宽和数量 | 显式 N、Q prime 位宽、数量和 prefix levels |
| 分布 | 实际 secret/error law；公开加密 ephemeral 固定 CBD1 | 同左 |
| 电路 | 1…8 层普通二输入乘法，包含 square | 静态公开操作 DAG，操作数引用此前节点 |
| 换钥后端 | signed Radix16 或 Hybrid alpha1 | 指定 signed radix 配置或实际 Hybrid 分区及 P |
| 降模 | 每层内部缩基、HPSPOVERQ、恢复外部 level 0 | 显式 p-preserving prime drop |

生成器有限地搜索实际素数，并验证素性、互异性、`q < 2^62` 和 `2N | q−1`。
BGV 还保留 `q_i ≡ 1 (mod p)`；Hybrid key P 与 Q、p 必须互素。
普通低层参数/context 构造器的原契约不因新增请求而变成通用 prime 认证或完整预算。
带自选 Q 的 context 进入 planner 时同样验证 primes。

N、prime 数量和位宽仍由调用方明确选择。请求成功只生成候选配置，完整电路可能拒绝；
拒绝信息指出公开条件、边界或节点及所需容量，可据此调整资源后重新准入。
这里没有任意程序编译器，也没有自动寻找最小 N/Q 的优化器。

BFV 的每层两个输入均须满足上一层公开误差界，消息采用全范围 canonical 系数界。
该族不自动包含加法、旋转、永久 drop 或其它乘法后端。现有低层 Exact/HPS 仍可用，
但不能把本族的账本当作那些流程的完整证书。
BGV 支持 fresh public/private、加法、明文加乘、乘法及 relinearization、automorphism、
key switch 和 drop。后续操作须实际使用 plan 返回的相应 level key 配置。
同一 context 的真实 secret 关系、实际消息和诚实建钥仍是调用方的语义前提。

## 预算的含义

账本只使用公开参数和 sampler 的硬支持界，不读取 secret 或 ciphertext phase。
CBD 使用精确有限支持；Gaussian 使用实际实现的截断支持。它不是理想无界 Gaussian
的尾概率证明。通用支持界为 `H=N*secret_maximum_magnitude`；BFV 还利用固定重量、
固定 composition 和 block-binary 的公开 L1 界。BGV 暂用通用支持界。
拒绝可能来自保守性，不能反推实际解密一定失败。
Slot 值小也不意味着编码后的明文系数范数小。

BFV 的逐层账本列出输入缩基、固定 Δ 漂移、HPS 变换残差及整数 phase quotient、
tensor、component rounding、key sampling/residual 或 ModDown、scaled restoration，
以及完整 decoder 容量和剩余界。Fresh public 加密计入公钥误差与 CBD1 ephemeral、
新 body/mask error 和 unsigned 消息 lift 漂移。
完整推导见 [BFV 工作基](bfv-working-basis.md)。

BGV 直接跟踪意图中的整数 phase 上界 Z，因此乘法的明文 carry 也在 `N*Z1*Z2`
之内。每节点检查 `Z <= floor(Q/2)`，key residual 按 relin 的 s² 或其它角色的 s
计入；drop 计入 p-preserving component corrections。账本列出每项、level、容量和余量。
此界可以偏保守，但不会用一个未经证明的小误差替换整个乘法 phase。
数学身份见 [BGV 求值](bgv-evaluation.md) 和 [Hybrid keys](native-hybrid-keys.md)。

这些账本只准入所声明的普通单 owner 电路。Collective key、raw tensor、Flexilect 的
mixed lookup、统计 flooding 和相关联合 transcript 需要它们自己的完整分析。

## 安全输入与离线参考筛查

`plan.security_inputs()` 返回独立于正确性准入的公开输入库存，状态为
`RlweSecurityStatus::NotEvaluated`。它记录实际 N、sampler laws、exact modulus product
和 bit length。该库存直接借用已准备的 sampling 状态，避免按拆出的 law 重建 Gaussian
表；允许报告不同 basis，仍不把诊断当成 context/key 绑定。顶层 public Q 在 ciphertext
drop 后仍然暴露；每个实际使用的 Hybrid
key 记录自己的 prefix QP。BFV computation-only P 不含 secret-bearing 样本，
不计为一个更大的 RLWE 暴露模数。不同域也不相乘成一个虚构的观测模数。

[离线适配器](../../scripts/screen_scheme_parameters.py) 使用显式指定的
[lattice-estimator](https://github.com/malb/lattice-estimator) checkout，支持 CBD、
uniform binary/ternary 的直接分布映射。其它分布直接拒绝，避免按相同方差替换。
输入 JSON 的每个域明确给出 N、有序 Q/key P、分布、独立 LWE 代理样本数和目标指数。
输出记录 estimator commit/源码 hash、Sage 版本、输入及适配器 hash、每项成本和有限
参考目标是否满足。失败的模型会使命令失败，部分输出带 `complete=false`。

在已安装 Sage 的 Python 环境中运行：

```sh
python scripts/screen_scheme_parameters.py \
  --estimator /path/to/lattice-estimator \
  --input guides/development/data/ordinary-rlwe-reference-input.json \
  --output /tmp/ordinary-rlwe-reference.json
```

仓库附有[输入](data/ordinary-rlwe-reference-input.json)和[结果](data/ordinary-rlwe-reference-result.json)。
它们只比较 ADPS16/MATZOV 的 primal-USVP、primal-BDD 和 dual-hybrid 模型：

| 示例域 | N | 暴露位数 | 所列模型最小参考成本指数 | 对目标128的有限参考结果 |
| --- | ---: | ---: | ---: | --- |
| BFV profile public Q | 16384 | 240 | 217.248 | 满足 |
| 同族较低工作层 Hybrid QP | 16384 | 240 | 217.248 | 满足 |
| 明确不安全的小测试域 | 128 | 60 | 11.680 | 不满足 |

这些示例使用实际 CBD1 secret、CBD21 error，选择 `m=N²` 的独立 bare-LWE 代理。
它是显式参考假设，不是从 RLWE 的相关 ring rows 得出的独立样本证明；也不穷尽
algebraic/BKW 等攻击，不能据此升级为完整128位安全。前两行也不能覆盖所有自选配置。
任何新配置仍须对实际暴露域重新评估。结构化 RLWE、相关/circular evaluation keys、
多用户联合材料及协议归约仍需另行论证；库不会根据本结果自动放行这些安全结论。

## 运行与覆盖

```sh
cargo run -p primus_bfv --example working_basis
cargo run -p primus_bfv --example working_basis -- --radix
cargo run -p primus_bgv --example leveled_coefficients
cargo run -p primus_bgv --example leveled_coefficients -- --hybrid
python3 scripts/check_scheme_consumers.py
```

示例和测试把整数账本与真实 ciphertext 工作流一起核对；参数数学的独立 oracle、
错误边界和既有在线分配检查各自保留。一次解密成功不替代预算或安全估算。
新增计算均位于参数/准备阶段，Flexilect 默认参数和在线四轮路径保持原有契约。
