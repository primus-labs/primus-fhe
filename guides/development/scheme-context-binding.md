# BFV/BGV 的 context、level 与 raw 互操作

普通调用沿一条实际资源链使用：参数移入 context，client 和公钥/求值键从该 context
生成，prepared operation 借用这些资源，密文输出也由这个 context 分配。密文保存
不可变的本地 context/level 关系；克隆与借用 view 保留关系。借用 view 不复制密文
数组；克隆 owned `Vec` 密文仍会复制它的数据。

BGV 密文还保存随实际运算历史变化的 `correction_factor()`，克隆和不可变 view
也保留它。它是消息缩放状态，不是 context 或 level 的身份：同一 level 的密文可能
具有不同 factor，求值器按实际 factor 对齐加减法。BGV 输出直接传 `&mut ciphertext`，
不再提供 `as_mut_view()`，以便输出数组与 factor 一起更新。BFV 的缩放语义保持独立。

这项绑定防止把同尺寸但不同 context、不同 level 的对象意外组合。它不证明外部数组
采用了正确秘密，不认证 `AsMut` 改写后的内容，也不建立噪声预算或密码安全证明。

## 普通调用与实际层级

以 BGV 为例，BFV 使用对应的同名方案类型：

```rust,ignore
let context = BgvContext::try_with_levels(parameters, 3)?;
let mut client = BgvClient::generate(&context, rng);
let public_key = client.public_key(rng);
let mut encryptor = context.public_key_encryptor(&public_key)?;
let mut evaluator = BgvEvaluator::new(&context, 0);
let mut output = context.new_ciphertext(0);

let ciphertext = encryptor.encrypt_centered(&message, rng);
evaluator.add_plain_to(&ciphertext, &offset, &mut output, PlaintextEmbedding::Centered);
let recovered = client.decrypt(&output);
```

`client.decrypt(&ciphertext)` 和 `decrypt_to(&ciphertext,&mut plaintext)` 使用密文记录的
level，不再重复填写。Level0 使用完整有序 Q，level l 移除尾部 l 个 primes，N 不变。
`try_with_levels` 只准备所请求的前缀；调用方仍显式决定何时 drop，库不自动消耗 level。

输入、输出与 prepared operation 的已绑定 context/level 必须一致。相邻 drop 的输出
由 `context.new_ciphertext(level+1)` 分配；它不是把原密文改标签。两个独立创建的
context 即使 N/Q/p 和共享 table 相同，也不自动成为同一个本地 owner。配对 BFV/BGV
context 可以共享不可变 NTT 表，方案语义及其本地身份仍各自保留。

密文相等比较也包含其已记录的 context/level，BGV 还包含 correction factor；
raw 与 bound 容器不会仅凭相同数组比较为同一个对象。若要比较公开数值 payload，
比较 `as_ref()` 返回的字节/word切片。
对象或数组相等都不证明实际 secret、ceremony 或一次性授权相同。

求值键按实际使用的 role/level 生成，`Multiplication`、`Relinearizer`、`Automorphism`
和 `KeySwitcher` 从实际 key 推导 level，并在 prepare 时检查其 context。不为一个
示例预建全部 levels，也不通过截断高层 key columns 冒充低层 key。相同 level 的多个
角色可以共享 `radix_key_parameters` / `hybrid_key_parameters` 的不可变算术资源，
自己的 columns、随机性及 mutable scratch 仍独立。

[leveled BGV](../../crates/primus_bgv/examples/leveled_coefficients.rs) 展示只生成所需的
level0 relin、level1 automorphism/换钥，以及两次 drop；恢复直接使用最低层密文。
[BFV working basis](bfv-working-basis.md) 的外部 level 可以始终为0，每个 step 的
内部 working basis 和 key 却不同，不能按外部 level 简单去重。

## Raw 数组与检查后的绑定

`BfvCiphertext::from_raw(data)` / `BgvCiphertext::from_raw(data)` 包装物理
`[c0,c1]` 存储，`zero_raw(len)` 分配同类高级工作缓冲。BGV 的这两个构造入口明确
声明 factor=1，不能用来丢弃已有密文的非一 factor。它们要求调用方维护实际 basis、
NTT 约定、level、secret 和数值范围。Raw quadratic 也保留其独立角色；
BFV 已缩放 quadratic 不能作为 fresh lookup 的未缩放 tensor 使用。

需要把 factor=1、已知来源的数组交给普通恢复时，消费整个 raw container：

```rust,ignore
let raw = BgvCiphertext::from_raw(words);
let ciphertext = context.try_bind_ciphertext(raw, level)?;
let recovered = client.decrypt(&ciphertext);
```

一般 BGV 链的外部密文需要携带实际 factor，不能从 level 推导。使用
[`BgvContext::try_import_ciphertext`](../../crates/primus_bgv/src/context.rs)：

```rust,ignore
let ciphertext = context.try_import_ciphertext(words, level, received_factor)?;
let recovered = client.decrypt(&ciphertext);
```

这个入口要求 `0<received_factor<p` 且 `gcd(received_factor,p)=1`，然后执行同样的
长度、canonical residues 与 context/level 检查。它不认证该 scalar 与数组的关系。
调用方必须确认其 phase 和 factor 的约定与 Primus 相同，并把 factor 与整个密文一同
认证；只复制 physical words 会丢失消息语义。库不提供任意公开 factor setter。

`try_bind_ciphertext` 在这次显式入站中验证完整长度及 canonical residues，再保存实际
context/level；已有匹配绑定的输入也扫描，因为 `AsMut` 可以改写数组。输入若已有
绑定，必须属于同一 context 和 level；接口不提供 foreign retag。普通算术只做 O(1)
身份/level/形状检查，不逐系数重复准入；推荐链不在每一步再次调用此导入接口。检查
通过不证明该数组的实际 NTT 或 secret 来源：调用方必须先确定这个数学关系。
例如从 raw GLWE 转入 BFV 时，还须按[phase 约定](rns-phase-conventions.md)进行符号
转换。共享数字或一遍 canonical 扫描不能代替它。

高级恢复仍可显式使用 `client.decrypt_at_level(raw,level)` 或
`decrypt_at_level_to(raw,level,&mut plaintext)`。若输入已绑定，这些入口也检查原有
context/level，不能借显式 level 绕过错绑定。低层 `BfvSecretKeyContext` 与其显式恢复
workspace 保留独立借用接口；[explicit coefficients](../../crates/primus_bfv/examples/explicit_coefficients.rs)
展示 raw 工作区复用、消费式 checked binding，再交给普通 client 恢复。

对 `AsMut` 的访问只借出原数组，不更换 context/level 绑定或 BGV factor。调用方可以
写入任意值，因此必须维护数值及来源合同；绑定不是数组完整性认证。不要通过先拆 raw 数组再重新
包装来掩盖普通流程的 context 错配，除非确实完成了该高级导入所需的数学验证。

## Key 绑定的范围

普通 public/evaluation key 绑定其生成 context 和实际 level；相同 N/Q/p 的另一个
context 不能仅凭数值相同使用它。Ciphertext 仍没有认证真实 secret 的密码证明。
同一个 context 内若创建 Alice、Bob 两个 client，把 Bob 的 relin key 用于 Alice 的
密文仍违反 same-secret 前提。换钥必须按真实 source→target 关系生成，普通恢复也须
选择真正的接收方。该关系仍由调用方维护；不能把 context 检查称为 key possession
证明、secret 等价证明或对任意 raw 导入的认证。

实际 secret、ephemeral、恢复 phase 和 flooding 的擦除沿各自 owner 合同执行。
普通 evaluator scratch 不因为保存本地身份而获得新的秘密存储或跨 worker 共享语义。

## Collective 与安全 opening 的分工

FHE collective plan 组合独立加法 share，生成 aggregate secret `S=sum(s_i)` 下的
公钥与 role keys。最终 key 属于这个 aggregate 目标，不能等同任一个 share client。
Plan 的本地身份用于拒绝错 plan/context/round 的算术对象，不证明每条消息来自正确
参与者，也不证明 roster 完整、实际抽样或恶意安全。

外围协议负责认证 roster/session/role/source/target、拒绝重复及缺失 owner、绑定
准确冻结的首轮结果，随后消耗一次性授权并加入完整 fresh privacy flood。
`partial_phase_to` 仅计算物理 `c1*s_i`，不在每份 share 中去除 BGV factor；直接公开
它不构成安全 threshold opening。BGV 协议还须认证完整密文的 factor；合成所有物理
shares 与 c0 后，先取 `center_Q(phase) mod p`，再乘一次 `factor^-1 mod p`。
`contribution_count` 只能表达算术聚合进度，数量达到 G 不能证明 sender 集合正确。

[BGV collective 示例](../../crates/primus_bgv/examples/collective.rs) 是本地算术演示，
不包含认证传输或安全 opening；[native collective/lookup 契约](native-hybrid-keys.md#collective-roles-and-fresh-lookup)
规定共同 mask、cross terms、独立 fresh lookup 和 consuming/erasing states。
完整协议应继续使用其既有授权、roster 和 flooding owner，不能用本地 context 标签替代。

## 验证与限制

基础/进阶示例分别通过普通依赖的独立 consumer 使用这些接口，不继承主 workspace
的测试依赖或合并 features。小参数回归保护同形不同 context、错 level、借用 views、
raw 绑定及写入/RNG 前拒绝；原独立整数/DFT/phase、dirty scratch 和零临时分配
测试继续保护不同的数学与资源合同。

普通 BGV 支持与 p 互素的一般 prime 链及带 factor 的外部密文导入；其声明电路准入见
[BGV workflow](../../crates/primus_bgv/README.md#generate-parameters-and-admit-a-declared-circuit)。
这不放宽 Flexilect 自己的 per-prime q_i≡1 mod p、factor=1 与桥接参数限制。
这一层不提供持久化身份、跨进程完整建钥导入或生产多选举联合安全证明。
跨进程导入必须重建本地关系并认证外部数学来源，不能把
进程内指针或 identity token 序列化后当成认证证据。
