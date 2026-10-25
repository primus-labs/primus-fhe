# 仓库开发规范

适用于整个仓库；子目录 `AGENTS.md` 可补充或覆盖。Primus FHE 是持续开发中的 Rust workspace，暂不承诺稳定 API。

## 优先级与范围

依次优先：数学及表示/布局正确性 → 热路径性能与零额外分配 → 简单明确的所有权和工作区契约 → 可读、可维护 → 少而聚焦的测试、基准与文档。

- 开始时检查 `git status`、相关暂存/未暂存差异及本次目标涉及的文档，保留用户修改和暂存状态，不自动重开已完成的全库整理。
- 修改须最小且完整；有实质收益可破坏 API，但同步 workspace 调用方、测试、示例、基准和双语 README，不留无实际需要的兼容层、废弃代码或导入。
- 规划、分析、审查本身不授权改源码；遵循会话中已有授权，无关问题只报告。未经明确要求，不 stage、unstage、commit、amend 或 push；提交使用简洁 Conventional Commit，不加协作者元数据，无关修改分开。
- 成员见根 `Cargo.toml` 的 `crates/*`；跨层修改从底层向调用方推进。`temp/` 仅供参考，不修改其中外部项目。仓库已配置 `target-cpu=native`，不在命令中重复设置。

## API 与契约

- 优先已有类型、普通函数、固有方法、泛型/trait 和切片。新抽象须集中真实不变量、消除已确认重复、防止误用、隔离不同表示或有实测收益；参数重复、存在分支或假想消费者不足以成立。
- 实现前先查依赖层已有接口，入口见[库使用导航](guides/development/README.zh_CN.md)。完整多项式/密文及其子结构优先使用语义迭代器；标量、gadget 权重或无对应类型的分块使用 slice iterator。迭代器会略过不完整尾块，`zip` 只消费共同前缀；公开边界仍须验证完整长度和配对数量。
- NTT、Fourier、CRT/DCRT 等保留必要差异，不用万能 trait 隐藏数值契约。宏用于稳定重复、不变量生成或必要编译期工作，并权衡诊断和维护成本。
- 名称表达数学角色和表示，同一角色跨 crate 统一；函数族统一词干及 `try_`、`lazy_`、`*_assign`、`*_to`、`*_slice` 语义。参数按 `input/lhs/rhs/acc/output/scratch/context/modulus` 等角色命名，同层顺序一致，不强求不同契约同名或跨层统一参数顺序。
- 构造器、访问器和纯计算在丢弃结果通常是错误时使用 `#[must_use]`；原地操作不添加。
- rustdoc 说明签名无法表达的输入范围、归一化、表示/布局、输出位置、清零责任、scratch 和可能的部分写入；非平凡内部函数解释算法原因，机械转发与显然 helper 不复述代码。
- `# Panics` 记录实际检查/转换失败；`# Correctness` 记录未检查的数学与表示前提。继承底层超出 trait 保证的条件时引用原契约，不暗示违反数学前提必然 panic。

## 数值内核与检查边界

- 修改算术前确认输入域、输出范围、布局、归一化和精确缓冲区长度，核对溢出、窄化、移位、wrapping、惰性约简与 unsafe 前提。
- 在拥有契约的公开、批量或构造边界验证调用方数据；私有 kernel 使用已建立的不变量。不要逐层重复检查长度、模数、basis/table，也不在逐系数循环内重复检查或分派。
- 内部不变量通常用少量边界 `debug_assert!`；安全公开 API 独立承担的必要检查保留在 release。内存安全不能依赖 debug 检查。主动 panic 给出明确消息，避免调用方可触发的 `unreachable!`。
- 同一数学操作的 scalar/SIMD、NTT/Fourier、CRT/DCRT/RNS 路径核对语义并做聚焦差分验证，不强行统一表示。

## 性能、测试与基准

- 先选清晰且利于优化的实现，再测热路径；不假定 iterator、索引或 unsafe 更快。复用表示、预计算和 scratch，避免在线重复分配、clone、collect、变换及虚假的零长度缓冲区。
- 已知整除时优先 `chunks_exact(_mut)`；在内层循环外选择 scalar/SIMD 或特化 kernel，公开 wrapper 负责检查与调度。
- Criterion 每次迭代测一个明确工作负载，不手动重复以增加样本；非测量对象的 setup/分配移出计时。固定参数、CPU、工具链和 feature 比较等价工作，确认实际编译产物对应待比较源码；名称、throughput、`black_box` 对应真实负载，声称改善前必须实测。
- TFHE 接口以完整示例的用户流程为设计入口，测试和基准消费这些接口，不为测量单独扩展生产公开 API。TFHE 基准放在所属后端或 LUT crate 的 `benches/`；每个文件就地组织所需 helper，不引入集中 benchmark 包、跨文件 support 或报告框架。
- 性能优化以完整请求的可重复收益验收，同时评估额外存储、代码体积、接口与数值契约成本；阶段加速不能单独作为保留理由。
- 只保留保护独立契约、回归或持久诊断价值的测试/基准。优先固定 seed、确定性输入、独立 oracle、表驱动或差分；避免概率断言、不稳定阈值、标准库行为及机械转发测试。
- 普通测试（含密文端到端）优先使用能覆盖目标契约的小参数以降低 CI 成本；保留字宽、模数/舍入边界和必要的 SIMD/变换路径。大尺寸案例须有独立覆盖理由，示例/基准的代表性参数不自动成为普通测试要求。
- 公开行为放 `tests/`，私有 kernel 测试仅在有独立诊断价值时就地放置。普通测试不包含 benchmark、调试输出或大型统计；示例展示推荐工作流。
- 仅整理本次范围内的资产，区分重复与独立边界覆盖；完整 crate 整理才全面评估。删除本轮无长期价值的临时实验，纯审查只提建议。常用基准命令就地记录，nightly SIMD 命令只放 SIMD 基准中。

## 审查与文档归属

- Rust 代码审查、复审或基于源码的重构分析先明确范围，沿调用链核对数学、表示、资源和错误边界，区分确认缺陷与未验证路径。常规实现验证、仅依据已有报告规划，不自动升级为完整复审。
- **AGENTS** 只保存开发规范，不保存阶段进度或追加任务日志。
- `docs/` 仅保存本地计划与参考材料，不暂存或提交。跨库用法与契约放 `guides/development/`，性能取舍与测量证据放 `guides/performance/`，crate 专属说明放对应 crate；拟提交的源码和文档不得依赖 `docs/` 中的文件或链接。
- README/IMPLEMENTATION 面向使用者，说明用途、推荐流程、必要限制、features 和运行入口；不因内部重构或性能实验追加私有字段图、转发链、验证日志或阶段进度。
- 逐方法完整契约以拥有类型/方法的 rustdoc 为准，README 保留必要摘要与引用，局部理由放源码/基准注释。共同事实集中维护；删移文档前确认独有且仍适用的数学、表示和布局条件已有当前权威来源，不将长文整段平移到另一个目录。
- 专项文档保存跨层推导、取舍和必要测量证据；历史证据注明源码、负载与可重建限制，无当前决策价值的过程记录交由 Git。已完成计划压缩为入口索引，历史测试不替代当前验证，性能选择可在前提改变后复测。
- 同目录 `README.md` / `README.zh_CN.md` 同步章节、语言入口和链接；API、target、工具或文档退休时同步清理调用、覆盖和复现声明，删移文档后检查引用及锚点。

## 验证与交付

实现先窄后宽：

```text
cargo fmt --all
cargo check -p <crate> --all-targets
cargo test -p <crate>
cargo clippy -p <crate> --all-targets -- -D warnings
```

- 纯审查需要格式检查时用 `cargo fmt --all -- --check`，不格式化写入。纯文档检查内容和链接，必要时构建文档，不机械运行数值测试。
- Workspace 入口为 `just fmt-check`、`just check`、`just lint`、`just test`、`just simd`，先查 [justfile](justfile) 的实际 recipe/feature 覆盖；TFHE 使用 `just tfhe` / `just tfhe-simd`，后者需要 nightly。缺失覆盖补显式包命令，无关失败如实报告，不削弱检查。
- 普通 nextest 显式使用 `--lib --tests`；all-targets 用于编译/lint。Doctest 用 `just test-doc` 单独执行；Criterion smoke 用 `just bench-smoke <package> <target>`，不混入普通测试。覆盖与命令见[测试指南](guides/development/testing.md)。
- 交付前检查最终 diff、清理临时资产，说明行为/API 变化、实际验证、未验证路径及实质限制。
