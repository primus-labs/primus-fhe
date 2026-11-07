# BFV/BGV 公共对象持久化

普通调用使用方案现有的 context、密文和角色 key；持久化只负责把其公开内容变成可检查的字节容器。它不保存 secret、不保存本地指针，也不承担应用的认证、会话或安全预算证明。完整例子见 [BGV public_worker](../../crates/primus_bgv/examples/public_worker.rs)。

## 推荐流程

1. 原 client 保留自己的 secret 和工作区，导出 `context.to_public_bytes()`、`context.export_public_key(&key)`、所需 `export_relinearization_key` / `export_key_switching_key` / `export_automorphism_key` 及 `export_ciphertext(&ciphertext, level)`。
2. 接收方用 `BgvContext::from_public_bytes(bytes, limits)` 或 BFV 对应方法重建本地 context。`PublicObjectLimits` / `PublicObjectError` 在两方案 crate 中重导出，不需要额外包装类型。
3. 在这个 context 上调用相应的 `import_*`。接口检查完整数值参数和实际 NTT 表示，再将 owned 结果绑定到接收进程的本地 context/level。
4. Worker 通过正常 prepared evaluator 工作，导出结果密文；原 client 在原 context 上导入并恢复。不要直接将一个远端 context 的本地 owner 当成原 client 的 owner。

BGV 密文同时保存实际 correction factor，导入要求 `0<f<p`、`gcd(f,p)=1`。相同 level 的 factor 可以不同，不能只持久化 level/words 后默认 factor1。恢复仍先 centered CRT、模 p，再去除 factor。BFV 保存其独立的 plaintext 与 decoder gamma 参数，不借用 BGV 的消息尺度。

目前保存 degree-one 密文。正常 typed quadratic 运算仍可用，但不额外提供 raw quadratic 公共存储入口；有真实部署消费者后再扩展。此格式不导入 SEAL/OpenFHE 的密文或 key。

## 版本与表示

每个容器使用固定 LE u64 编码。前32字节为8字节 magic、u64 版本1、u64 方案标识及 u64 对象角色。角色0为 context，1为密文，2为公钥，3/4/5分别为 relinearization/switching/automorphism key。Typed import 只接受相应角色。所有尾字节均拒绝，不将共同前缀当作完整输入。

Context 记录完整 N、plaintext modulus、BFV gamma、已准备 level 数、ordered top Q、完整 secret/error law 描述及实际 NTT 指纹。导入先检查 N/levels/Q 的资源预算、sampler 字段和尾字节，再严格验证实际 NTT 素性及根阶条件，并调用方案原有 checked constructors。参数准备不返回安全等级。

NTT 指纹是完整 forward/inverse root 数组及其顺序的 SHA-256，包含 native u64 plus-phase representation version 标记。它在 context 中延迟缓存，未使用公共存储的路径不进行 hash。读取 context 时重建的表必须与该指纹一致；硬件选择不成为持久化的 process-local 身份。

其它对象携带完整公共 context 描述，直接与接收方已有 context 的描述比较，不为每份 key 再构造一次 context。原生密文以 `[c0,c1]`、每个 component modulus-major NTT 布局保存，并记录实际 level。公钥为完整 level0 零加密。求值键记录实际 level、角色 exponent、Radix 的 log/retained-column count，或 Hybrid 的 full-Q partition rule、ordered P 和 P-table 指纹，随后保存实际 Q 或 QP columns。只有 automorphism key 接受合法的 odd exponent。

导入列数组前，先验证完整几何及每个 residue 的 canonical 范围；key 的声明 backend、P/partition、列数、角色或 NTT 表示不匹配均拒绝。接收后重新建立本地 Arc/level 关系，不反序列化旧指针。公开 source/target secret 的实际关系仍不能从数组或相同参数推导。

## 资源与成本

`PublicObjectLimits` 同时限制整个 frame 的 bytes、N、basis 的 modulus 数、payload/preparation words 以及 Gaussian 标准差。部署应按预期 profile 收紧这些上限。Context 在准备 NTT/CRT/sampler 前，以 `16*N*Q*levels + 256*Q^3 + 16384*Gaussian实例数` 的保守 word charge 做准入，并检查所有乘积溢出；这是一项资源准入单位，不是精确 RSS。每个实际 Gaussian sampler 的附加16384 words 覆盖最多512层的 Ziggurat 持久数组与构建 scratch，亦覆盖 CDT 替代路径；Gaussian scale 另行在准备 sampling table 前检查。Key payload 及 Hybrid 的新 QP preparation 也在分配对应 owner 前检查。

完整 byte cap 不能替代派生资源检查：一个很小的 context blob 也可能声明巨大的 N/Q/levels。格式不接受这种声明后再尝试分配。长度、canonicality、全部尾字节和角色元数据检查属于冷导入边界，正常算术仍使用既有 typed owner 和 scratch。

独立导入多份 key 时，当前接口会各自准备相应 numerical metadata，包括 Hybrid P 表；它没有为尚不存在的整套 key-cache 消费者引入公共框架。若实际应用需要持久化整个 family，应根据 measured cold-load/RSS 决定共享方式。普通 client 的 secret 持久化、秘密 material cache、跨进程一次性权限或 key refresh 也不由这个格式提供。

## 认证与协议边界

这些容器的字段及 NTT 指纹不构成消息认证。攻击者可以替换整份合法对象，或伪造与其实际秘密关系不符的声明；应用必须认证完整容器及其 source/target、roster、session、round 和参数预算。结构校验不证明贡献诚实、RLWE 硬度、误差界或安全 opening。

版本化公共存储与在线协议 payload 分开。它不自动恢复应用曾删除的 schema/header，不改变 Flexilect 四轮选举消息，也不以短 seed 替代独立完整 uniform masks。具体部署的 plan 导入及 ceremony 消息认证由上层协议拥有。
