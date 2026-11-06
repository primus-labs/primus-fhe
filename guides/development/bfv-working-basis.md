# BFV临时工作基：HPSPOVERQLEVELED

此策略将外部Q中的密文临时缩减到较小prefix q=Q_l，在q中乘法和换钥，再恢复外部Q。
输入和输出的level及长度保持不变；恢复操作为`y -> D*y modQ`、D=Q/q，在保留limbs
乘D、其余limbs置零。它是scaled embedding，不是普通centered basis extension，也不是
永久`BfvModulusSwitch`。秘密和完整环维数N均不缩小。

实现沿用[论文2021/204](https://eprint.iacr.org/2021/204) Algorithm3的临时降基机制，
对两输入分别精确nearest-round，再使用当前HPSPOVERQ。它保留Primus固定
`Delta=floor(Q/t)`加密，显式计入相应漂移；没有把OpenFHE的经验cushion作为证明。
已核对[OpenFHE v1.5.1乘法](https://github.com/openfheorg/openfhe-development/blob/v1.5.1/src/pke/lib/scheme/bfvrns/bfvrns-leveledshe.cpp)
及[scaled embedding](https://github.com/openfheorg/openfhe-development/blob/v1.5.1/src/core/include/lattice/hal/default/dcrtpoly-impl.h)。
该实现的Remark3.4式fused-right优化是另一种残差路径，本实现不冒称已完成该融合。

## 普通入口与适用范围

```rust,ignore
let context = BfvLeveledRequest {
    poly_length: PolyLength::new(16384),
    plaintext_modulus: 65537,
    require_batching: true,
    ciphertext_prime_bits: 60,
    ciphertext_prime_count: 4,
    secret_distribution: SecretKeyDistr::SparseTernary,
    error_distribution: ErrorDistribution::CenteredBinomial { eta: 21 },
}.create_context()?;
let plan = BfvLeveledParameters::try_new(&context, 3, BfvLeveledKeyBackend::HybridAlpha1)?;
// client由该实际context生成；每个step的key/operation在请求前准备。
let keys = plan.steps().iter()
    .map(|step| step.relinearization_key(&client, &mut rng))
    .collect::<Result<Vec<_>, _>>()?;
let mut operations = plan.steps().iter().zip(&keys)
    .map(|(step, key)| step.prepare(key))
    .collect::<Result<Vec<_>, _>>()?;
```

完整例子为[working_basis.rs](../../crates/primus_bfv/examples/working_basis.rs)。它验证
三次square后在原外部level0恢复`(2+X)^8`；`--radix`切换普通key后端。

`BfvLeveledRequest::create_context`根据N、明文系数模数、Q的prime位宽和数量、
secret/error law生成一个数值context；生成本身不承诺某个深度可行。设定
`require_batching=true`时，还检查t为素数且`t=1 mod 2N`。普通系数明文不要求该条件。
Q以及实际Hybrid key P验证素性、互异性、`2N` root条件和`q<2^62`；NTT表构造成功
本身不能代替这些检查。自选prime链可由已有`BfvContext`直接进入同一`try_new`，
不必先转成request再拆分重建。当前要求default gamma及完整prefix codecs。

`BfvLeveledParameters::try_new`对depth 1..=8的普通binary multiplication族作完整
预算：两输入都必须不超过上一层的error界；square是其特例。支持现有合法binary、
ternary、fixed-weight/block及实际截断Gaussian secret sampler，以公开hard support
计算L1界；支持CBD和实际截断Gaussian error sampler。public encryption的ephemeral
仍固定CBD1，不能把它误写成与secret相同的law。每步实际drop；找不到完整可行schedule
就返回包含stage、input、required、available的错误，不静默退化为全Q策略。

计划公开`fresh_error_ledger`、每层`error_ledger`、codec capacity及剩余error capacity。
它们分别列出公钥误差、fresh c0/c1误差、unsigned embedding漂移、输入round、HPS
residual/centered wrap、phase quotients、tensor/component round、key采样与radix
低位残差或Hybrid ModDown，以及scaled restoration和fixed-Delta drift。
所有整数预算精确上取整。`security_inputs()`单独报告实际data Q和被使用的working
Q/key-P域、secret/error laws和hard supports；状态为`NotEvaluated`，不是128位安全证书。
计算P只参与正确性，不算作公开evaluation key的暴露模数。

原`BfvLeveledProfile`保留两个有实际回归消费者的固定N/Q geometry；使用它们时，
旧参数与算法不变。`plan.profile()`对匹配几何返回`Some(profile)`，自选几何返回`None`。
以下是旧CBD1/CBD21、t257/65537配置的已认证结果，不是新搜索入口对全部law的保证：

| profile | t257最大已认证深度 | t65537最大已认证深度 |
| --- | ---: | ---: |
| N16384Q240 | 4 | 3 |
| N32768Q360 | 7 | 5 |

Radix16和Hybrid alpha1均得到上表；38个可行请求与26个超深拒绝，共64个profile/t/
backend/depth请求，与独立forward search一致。工厂实际准备并按working level共享
不可变Hybrid参数；`step.key_config()`仅克隆配置/Arc，不重建NTT。计算P与key P角色
分开；即使某些prime数值相同，也不把计算P算入密钥暴露模数。

`step.relinearization_key`检查client的实际context指针。`step.prepare`检查key的本地
context及实际level/backend，但不能证明不透明key的真实secret、采样来源或ordinary/collective身份。
正确使用仍要求本context按照预算所列law诚实生成ordinary client和ordinary keys；
旧profile数值表使用CBD1/CBD21，custom配置使用其报告的实际law。不能把
同geometry的collective key、不同secret或超出支撑的导入key借来使用此预算。

该计划只覆盖给定binary族。插入rotation、switch、add、permanent drop或其它运算必须重算相应
误差；不能把本步输出E当作任意后续操作的授权。它也不搜索任意目标安全等级或证明
相关密钥的计算安全。

## 高级算术与所有权

`BfvLeveledMultiplication::try_with_auxiliary_moduli(context, external_level,
working_relin_key, P)`显式选择两种实际level与计算P；`try_new`自动准备working HPS的
资源P。自动P只负责其epsilon资源预算，不能代替完整电路证书。实际key必须在较小
工作level生成，不能截取全Q Radix columns或改标签冒充它。

复用一个context的NTT/codecs，不创建小context。临时component reductions、HPS、
quadratic/degree-one buffers与恢复scratch归operation。`multiply_to`、`square_to`、
`square_assign`及以下working-key路径均零在线分配；并行请求分别持有mutable owner。
普通确定性key误差界允许重用相同配置的ordinary key；相同数值配置的prepared owner
也可串行复用。给每个step各准备一个owner更直接，但会占更多scratch。

`BfvRelinearizer`、`BfvKeySwitcher`、`BfvAutomorphism`分别提供
`try_with_working_level(context, external_level, actual_working_key)`。它们只round将被
switch的c2/c1，在working basis求key product并scaled-restore，然后加回原Q的c0/c1
或其automorphism。原分量不跟着整体round，避免不必要误差；零gap退化为原路径。

## 可检查误差界

以下均为negacyclic多项式的infinity/L1界。设Q=Dq，r=Q modt，H=1+h、h≥||s||1；
两个输入的canonical消息界为M和M'，phase误差为E、F。记L为working prime数：

```text
U  = (E+r*M/t)/D + H/2
U' = (F+r*M'/t)/D + H/2
V  = (P/q)*U' + L*H
ZA = H/2 + M/t  + U/q
ZB = H/2 + M'/t + V/P
W  = N*((q/P)*(M+t*ZA)*V + U*(M'+t*ZB) + (t/P)*U*V)
     + (1+h+h²)/2
Eout <= D*(W+Kwork) + r*Mout/t.
```

工作phase写作`(q/t)*m+u+q*zA`和`(P/t)*m'+v+P*zB`。中心化component的幅度
给出ZA/ZB，HPS的centered wrap kappa包含在zB中，不能删掉这些phase quotient项。
最终消息modt的进位在有理Q/t表示中成为Q倍数；恢复fixed Delta后只另付r*Mout/t。
生产实现每处取精确整数ceil，全部对上取整，不使用浮点阈值。

ordinary full signed radix16的working key界为`N*d*2^15*eta+rho*hsource`，其中
d=floor(bitlen(q)/16)、rho为未保留低位的半径；relin用hsource=h²。Hybrid alpha1为
`ceil(N*eta*sum(qi-1)/Pkey+(1+h)/2)`。eta是实际error sampler的hard support，不能用于collective的E0*S、
(U−S)E1、E2聚合误差。工作key误差必须先加进W再乘D。

Standalone working-key操作给输入误差另加`D*(Kwork+hsource/2)`；relin同样用h²，
switch/auto用source secret的L1界。完整外部codec检查采用严格整数不等式：

```text
2*gamma*(t*Eout+r*Mout) + 2*Q*#Q < Q*gamma.
```

Fresh public encryption使用`eta*(Hu+1+Hs)+r`，其中`Hu=N`来自固定CBD1 ephemeral，
`Hs`来自实际secret sampler的公开支撑（固定weight可使用其精确L1上界）。四项分别为
`eta*Hu`的shared public-key error、`eta`的e0、`eta*Hs`的e1S及`r`的unsigned
到centered fixed-Delta漂移。Gaussian界对应实现的有限截断支撑；这里没有另加概率尾界。
原生BFV plus phase始终为c0+c1*s。

## 协议与性能边界

该机制仅用于普通BFV。BGV保持其p-preserving语义；Relect/Flexilect的raw tensors、
BFV scalar expansion和fresh unscaled mixed lookup不自动进入ordinary乘法缩放。
同级SSLE参数账本和one-use opening不能借用本普通工厂的误差证书。

默认乘法仍为Exact，原HPSPOVERQ自动P也不自动改成Leveled。完整请求要分别比较
默认HPS、相同P控制组、满足相同完整误差条件的基线，以及实际工厂计划；同时报告
key与operation scratch、setup、RSS和phase，不能只看较小tensor的速度。

```sh
cargo run -p primus_bfv --example working_basis
cargo run -p primus_bfv --example working_basis -- --radix
cargo test -p primus_bfv --test working_evaluation_keys --test leveled_multiplication --test leveled_parameters
cargo bench -p primus_bfv --bench working_basis -- --test
```
