# primus_ntru 基准

[English](README.md) | 简体中文

> [!WARNING]
> [Primus FHE](../../../README.zh_CN.md) 处于实验阶段，API 与数值契约尚不稳定，可能随时发生不兼容修改。

## 负载

| Target | 计时工作 |
| --- | --- |
| [encryption](encryption.rs) | 普通消息加密及未解码相位提取 |
| [primitives](primitives.rs) | Key switching、系数/变换域自同构、trace/reverse trace、投影、部分展开及 scheme switching |
| [constant_gadget](constant_gadget.rs) | 常数 NLev 生成及 8 个有符号 NGSW 控制的批量生成 |
| [lwe_return](lwe_return.rs) | Q→q 转换、提取及 LWE key switching；逐个返回与共享输入批量返回对比 |
| [ternary_cmux](ternary_cmux.rs) | 用加密控制比较一次融合 ternary 旋转与两次 binary CMUX |

密钥、表和缓冲区分配在计时外准备；加密计时包含采样、编码及所需变换。参数和固定 seed 就地记录在各文件中，这些负载不证明不同后端具有相同安全性。

相位提取不包含解码；trace 与 reverse trace 的输出尺度不同。`lwe_return` 不包含盲旋转，输入为规范系数多项式。`ternary_cmux` 比较两条路径的完整旋转，Fourier 结果可能有不同的舍入误差。

## 运行

```sh
cargo bench -p primus_ntru --bench encryption --features ntt,rustfft,tfhe-fft
cargo bench -p primus_ntru --bench primitives --features ntt,rustfft,tfhe-fft
cargo bench -p primus_ntru --bench constant_gadget --features ntt,rustfft
cargo bench -p primus_ntru --bench lwe_return
cargo bench -p primus_ntru --bench ternary_cmux --features ntt,rustfft,tfhe-fft
```

追加 `-- '<regex>'` 筛选用例，或追加 `-- --test` 只做 smoke check、不采集计时样本。以上 features 包含各 target 必需的 FFT engine。验证命令见 workspace [测试指南](../../../guides/development/testing.md)。
