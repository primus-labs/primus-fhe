# primus_glwe 基准

[English](README.md) | 简体中文

> [!WARNING]
> [Primus FHE](../../../README.zh_CN.md) 处于实验阶段，API 与数值契约尚不稳定，可能随时发生不兼容修改。

## 负载

| Target | 计时工作 |
| --- | --- |
| [encryption](encryption.rs) | 私钥/公钥加密及私钥解密，含系数 NTT 路径；GLev/GGSW 生成及 8 个常数 GGSW 的批量生成 |
| [primitives](primitives.rs) | Trace/reverse trace、投影、部分/完整展开、trace packing 及直接 Fourier 自同构 |
| [key_conversion](key_conversion.rs) | 独立密钥 LWE packing，以及系数 GLev 到变换域 GGSW 的 scheme switching |

密钥、表和缓冲区分配在计时外准备；加密计时包含采样、编码及所需变换。参数和固定 seed 就地记录在各文件中，这些负载不证明不同后端具有相同安全性。

普通与 reverse trace 的输出尺度不同。投影和部分展开使用相同的零尾部消息，throughput 按输出消息数报告。Trace packing 使用展平 GLWE 秘密及间隔槽位；独立密钥 packing 使用连续槽位，应按所需操作比较这些端点。

## 运行

```sh
cargo bench -p primus_glwe --bench encryption --features ntt,rustfft
cargo bench -p primus_glwe --bench primitives --features ntt,rustfft,tfhe-fft
cargo bench -p primus_glwe --bench key_conversion --features ntt,rustfft
```

追加 `-- '<regex>'` 筛选用例，或追加 `-- --test` 只做 smoke check、不采集计时样本。以上 features 包含各 target 必需的 FFT engine。验证命令见 workspace [测试指南](../../../guides/development/testing.md)。
