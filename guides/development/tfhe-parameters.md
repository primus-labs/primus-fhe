# TFHE experimental parameter directory

These configurations are experimental examples and benchmark fixtures, not certified parameter sets. Conditional model screening, successful construction and sampled known-result checks do not certify security or complete decryption-failure probability. Equal dimensions across backends do not establish equivalent security, precision or work.

The current sources below own the numerical choices. Operation contracts belong to the [bootstrapping guide](bootstrapping-contracts.md); execution commands belong to the [testing guide](testing.md). This directory does not prescribe ordinary-test sizes.

## Scope of paired parameter entries

Start from the concrete backend's `experimental` operation config. Examples fix `Word=u64`; the config supplies key domains and default messages, while the example supplies the function and its consumers.

| Backend | Config source | Complete workflows |
| --- | --- | --- |
| GLWE NTT | [experimental.rs](../../crates/primus_tfhe_glwe_ntt/src/experimental.rs) | [Examples](../../crates/primus_tfhe_glwe_ntt/README.md#operation-examples) |
| GLWE Fourier | [experimental.rs](../../crates/primus_tfhe_glwe_fourier/src/experimental.rs) | [Examples](../../crates/primus_tfhe_glwe_fourier/README.md#operation-examples) |
| NTRU NTT | [experimental.rs](../../crates/primus_tfhe_ntru_ntt/src/experimental.rs) | [Examples](../../crates/primus_tfhe_ntru_ntt/README.md#operation-examples) |

Application parameters are maintained in the sibling repositories: [OMR two-stage presets](../../../primus_omr/crates/primus_omr/README.md#parameters-and-contracts) and [high-precision lookup presets and model limits](../../../primus_high_prec_lut/guides/development/parameters.md).

Here t is the message modulus, not the number of padded inputs: a front-half input at t=32 has 16 values. Input and output message moduli may differ. PBS/ManyLUT outputs are Rounded, MVB outputs are Scaled, and CBS outputs use gadget scaling rather than an ordinary output codec.

| Config | Teaching workload and message domains |
| --- | --- |
| `CLASSIC_PBS_U64` | All three backends: Rounded 32→32, classic binary. Form z=2x+y, apply score=min(z,6), then price=2*score+[score>=4]. |
| `CLASSIC_PBS_U64` with `messages=PbsMessageConfig::new(4)` | Boolean access rule: admin OR (member AND NOT revoked), Rounded 4→4. |
| `SPARSE_PBS_U64` | Same scoring pipeline and 32→32 messages, fixed-weight binary sparse BR with three copies and 64 buckets. |
| `CLASSIC_MANY_LUT_U64` | Rounded 16→8, inputs 0..8, two lanes/stride two: grade=x/2 and flag=[x>=5], then code=2*grade+flag. |
| `CLASSIC_THRESHOLD_MVB_U64` | Rounded t_in=128, inputs 0..64; 17 threshold flags with Scaled t_out=2. |
| `CLASSIC_CBS_U64` | Rounded t_in=8, inputs 0..4; predicate F=[m>=2] selects an encrypted fee vector, then encrypted extras are added. Candidates use Scaled t_ring=8. |
| GLWE `CLASSIC_CBS_U64` with `input_encoding=MsbBoolean` | CBS input t=2, bits at 0/round(q_external/2); NOT selects encrypted service limits. Ordinary PBS messages remain unchanged. |
| `SPARSE_CBS_U64` | GLWE only: the same CBS fee-vector workflow with fixed-weight sparse BR. |
| `CLASSIC_ONE_HOT_U64` | NTRU only: t_in=8/M=4; generate the three nonzero NGSW selectors and perform four-way CMux over encrypted records at t_ring=8, with C0 as default. |

Classic is the default for every entry except the two explicitly sparse configs. NTRU's fixed-weight one-hot config can also support sparse BR with corresponding material; this is a separate choice, not the default teaching path. See the [backend support guide](../../crates/primus_tfhe/README.md#selecting-blind-rotation).

## Moduli, geometry and secret domains

| Symbol | Representation and value | Current use |
| --- | --- | --- |
| Q50 | `BarrettModulus<u64>`, 1125899906826241 | u64 NTT examples and benchmarks |
| Q27 | `BarrettModulus<u32>`, 132120577 | u32 NTT dense PBS benchmark |
| Native32 / Native64 | `NativeModulus<u32/u64>`, implicit 2^32 / 2^64 | Fourier accumulator; also GLWE external modulus |
| q24 | `PowOf2Modulus<u32/u64>`, 2^24 | NTRU backend teaching configs |

These Barrett values fit `Q<2^(BITS-2)` and support the NTT lengths used here. Explicit powers of two use `PowOf2Modulus`; native moduli are implicit. GLWE Fourier TFHE uses Native accumulator moduli.

For the u64 configs, n denotes the small BR-control dimension in GLWE and the independent external dimension in NTRU. The GLWE teaching constants below have k=1 and q=Q; their contexts also support independent q/Q, demonstrated by `ntt_two_moduli`. NTRU uses independent external q and ring Q secrets; its backend teaching configs use q24.

| Family / configs | n / N | Small or external secret | Ring secret |
| --- | --- | --- | --- |
| GLWE classic PBS / Boolean | 866 / 2048 | Uniform binary | Uniform binary |
| GLWE sparse PBS / ManyLUT / MVB / sparse CBS | 728 / 1024 | Fixed-weight binary, h=32 | Sparse ternary |
| GLWE NTT classic CBS | 866 / 2048 | Uniform binary | Uniform binary |
| GLWE Fourier classic CBS | 800 / 1024 | Uniform binary | Uniform ternary |
| NTRU classic PBS / Boolean | 866 / 2048 | Uniform binary | Sparse ternary |
| NTRU sparse PBS / ManyLUT / MVB | 728 / 1024 | Fixed-weight binary, h=32 | Sparse ternary |
| NTRU classic CBS | 800 / 1024 | Uniform binary | Sparse ternary |
| NTRU one-hot | 800 / 1024 | Fixed-weight binary, h=32 | Sparse ternary |

GLWE teaching configs use `BootstrapKeyswitch` (BR→KS), except MVB, which uses `KeyswitchBootstrap` (KS→BR). The external LWE dimension is n in BR→KS and kN in KS→BR. Both orders return under their external secret. NTRU returns by coefficient Q→q switching, phase extraction and LWE KS. See [domain and return contracts](bootstrapping-contracts.md#ciphertext-domains-and-return).

`SparseTernary` has probabilities (-1,0,+1)=(1/4,1/2,1/4), not an exact Hamming weight. NTRU teaching configs sample f from this signed distribution and screen for backend invertibility/stability; it is not a `1+2F` distribution. The independent external fixed-weight secret and the conditioned ring secret have different roles. Sparse public-map conditioning is covered in the [numerical guide](bootstrapping-contracts.md#ternary-and-sparse-rotation).

## Noise by key role

All deviations use **coefficient units under the role's own modulus**. BR and KS
noise are independently configurable; teaching configs sometimes choose equal
values. CBS trace and scheme-switch rows use the ring encryption noise, with
separate decompositions and independently sampled keys. In GLWE KS→BR, fresh
external LWE encryption uses the ring/BR noise, not the small-LWE or KS-row noise.
Public-key encryption introduces additional public-key and combination errors.

Use the operation config's `bsk_gadget` and `key_switching` fields for
current row sampler values; `gadget` supplies the CBS decompositions. The default [discrete Gaussian sampler](../../crates/primus_distr/README.md)
is centered and truncated at inclusive magnitude `max(1,floor(12σ))`; σ is its
sampler parameter, not the measured noise of an evaluated ciphertext. Models must
also account for accepted-key conditioning and shared evaluation-key errors.

The NTT `CLASSIC_CBS_U64` uses q=Q50, rank one and independently sampled
binary secrets. Its padded t8 predicate `[m>=2]` was checked with a Scaled t8
CMux consumer and an LWE return. Other consumers need their own noise analysis.

| NTT classic CBS role | Coefficient-unit σ | `(log₂B,L)` |
| --- | ---: | --- |
| Fresh small LWE | 2303762004.9811506 | — |
| BSK | 6.4 | (15,2) |
| Binary reverse trace | 6.4 | (12,3) |
| Rank-one square SS | 6.4 | (12,3) |
| Output GGSW | Inherited evaluated noise | (8,2) |
| Return ring KS | 2303762004.9811506 | (3,5) |

The return target is the n866 secret padded with 1182 public zeros, not a fresh
2048-dimensional secret. A public BSK subset supplies 1732 independent scalar
LWE equations under the ideal independent-mask/error model. Limited classical
BDGL16/GSA estimates exceed 128 bits for that subset and a known-message fresh
oracle scenario; they do **not** certify the full public material. In particular,
correlated ring equations and the trace/SS/KS key-dependent messages require
separate treatment. The evaluated-noise model is conditional on captured data
and residual assumptions; complete request DFR remains unknown. These statements
do not apply to the unchanged Fourier or sparse CBS fixtures.

## Decomposition by operation

A `DecompositionConfig` fixes `log_basis` and optionally `level_count`. With
`level_count: None`, preparation chooses `floor(value_bits/log_basis)` levels;
this can still discard low bits. An explicit count does not extend to fill the
modulus. See [decomposition precision](../../crates/primus_decompose/README.md).

The backend config sources above own BR, KS, trace, SS and output gadgets; output
gadget precision is distinct from the internal switching bases. Select precision
and projection before generating keys. GLWE Fourier trace defaults to Ordinary.
NTRU NTT projection defaults to Separate, and the teaching CBS/one-hot presets
explicitly use PairedTrace. The [projection contract](bootstrapping-contracts.md#ntru-cbs-precision-and-projection-support)
also explains GLWE's trace-only Split35 context setting.

## Current backend benchmarks

The crate-local benchmarks consume the operation configs but measure the following specific work. They are not timings of every step in a teaching example.

| Target | Configuration and timed request |
| --- | --- |
| `pbs` | Dense classic u32/u64, fixed-weight classic u64 and fixed-weight sparse u64; one PBS of `F(x)=(3x+1) mod 16` at Rounded 32→32. The fixed pair shares the sparse config's numerical choices and changes only BR method. |
| `many_lut` | `CLASSIC_MANY_LUT_U64`: one two-output PBS returning grade and flag; no subsequent code-combining addition. |
| `mvb` | `CLASSIC_THRESHOLD_MVB_U64`: one factorized request returning all 17 threshold flags. |
| `cbs` | `CLASSIC_CBS_U64`: predicate [m>=2], CMux over two nonconstant encrypted candidates at t_ring=8, and coefficient 1 returned as LWE; no extra ring addition. NTT names include `n866_N2048` to separate the revised config from old n800/N1024 results. The `predicate_cmux_return` workload includes return cost and is not the former `predicate_cmux` measurement. |
| GLWE `cbs_identity` | Benchmark-local G1 NTT / G2 Fourier comparison configs; padded/MSB identity CBS, with separate CBS-only and CBS＋CMux cases. Fourier ordinary/Split35 select the trace representation. |
| GLWE `modulus_domains` | Benchmark-local q=Q/q1024, both PBS orders; NTT and TFHE-FFT. |
| `one_hot` | NTRU `CLASSIC_ONE_HOT_U64`: three nonzero NGSWs and four-way CMux at t_ring=8. |

Fourier benches select RustFFT, TFHE-FFT or both, using the same numerical config but engine-compatible material. Sources and commands: [GLWE NTT](../../crates/primus_tfhe_glwe_ntt/README.md#benchmarks), [GLWE Fourier](../../crates/primus_tfhe_glwe_fourier/README.md#benchmarks), [NTRU NTT](../../crates/primus_tfhe_ntru_ntt/README.md#benchmarks).

The opt-in PBS Low/High, identity CBS and modulus-domain comparisons own their parameters in the bench files, rather than the teaching constants above. Select them through the [benchmark guide](testing.md#tfhe-benchmarks); historical parameter mappings and results belong to the [comparison report](../performance/bootstrap-functional-comparison.md).

The dense PBS benchmarks provide explicit word-specific u32/u64 fixtures, rather
than casts of one config. Dense and fixed-weight PBS change geometry, secrets
and noise; only the fixed classic/sparse pair isolates the BR method. Consult the
bench-local config before comparing two timings.

## Evidence and changes to a workload

| Evidence | What it establishes |
| --- | --- |
| Config and constructor checks | Representable parameters, supported samplers, encoding/layout and applicable table/binding conditions; not actual secret identity or complete noise margins |
| Known-result checks in examples and benches | Sampled functional behavior when those workloads are run; not a coverage claim for every word, engine, secret or operation |

Changing message moduli, lane count, function, candidate range or chunk partition changes the error requirements even when existing keys remain compatible. Scaled MVB output is not automatically a valid Rounded PBS input. CBS predicates must be bit-valued for CMux, and arbitrary MVB factors can amplify noise far more than the threshold workload. Check the [operation's numerical contracts](bootstrapping-contracts.md) and [material pairing](composition.md#bind-material-before-evaluation).

A future security/DFR claim must specify its model and version, exact secret/sampler and conditioning assumptions, applicable functions, and complete error propagation including correlations. Finite historical diagnostics are not current validation; current checks and commands are described in the [testing guide](testing.md).
