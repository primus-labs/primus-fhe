# TFHE experimental parameter directory

These configurations are experimental examples and benchmark fixtures, not certified parameter sets. Conditional model screening, successful construction and sampled known-result checks do not certify security or complete decryption-failure probability. Equal dimensions across backends do not establish equivalent security, precision or work.

The current sources below own the numerical choices. Operation contracts belong to the [bootstrapping guide](bootstrapping-contracts.md); execution commands belong to the [testing guide](testing.md). This directory does not prescribe ordinary-test sizes.

<a id="scope-of-paired-parameter-entries"></a>

## Default experimental presets

Start from the concrete backend's `experimental` operation config. The preset supplies key domains and default messages. The u64 examples supply the function and its consumers, with explicit overrides in the [Block examples](#block-examples). See [current backend benchmarks](#current-backend-benchmarks) for timed workloads.

| Backend | Config source | Complete workflows |
| --- | --- | --- |
| GLWE NTT | [experimental.rs](../../crates/primus_tfhe_glwe_ntt/src/experimental.rs) | [Examples](../../crates/primus_tfhe_glwe_ntt/README.md#operation-examples) |
| GLWE Fourier | [experimental.rs](../../crates/primus_tfhe_glwe_fourier/src/experimental.rs) | [Examples](../../crates/primus_tfhe_glwe_fourier/README.md#operation-examples) |
| NTRU NTT | [experimental.rs](../../crates/primus_tfhe_ntru_ntt/src/experimental.rs) | [Examples](../../crates/primus_tfhe_ntru_ntt/README.md#operation-examples) |
| NTRU Fourier | [experimental.rs](../../crates/primus_tfhe_ntru_fourier/src/experimental.rs) | [Examples](../../crates/primus_tfhe_ntru_fourier/README.md#operation-examples) |

Here t is the message modulus, not the number of padded inputs: a front-half input at t=32 has 16 values. Input and output message moduli may differ. PBS/ManyLUT outputs are Rounded, MVB outputs are Scaled, and CBS outputs use gadget scaling rather than an ordinary output codec.

| Base config | Example workload and message domains |
| --- | --- |
| `CLASSIC_PBS_U64` | All four backends: Rounded 32→32, classic binary. Form z=2x+y, apply score=min(z,6), then price=2*score+[score>=4]. |
| `CLASSIC_PBS_U64` with `messages=PbsMessageConfig::new(4)` | Boolean access rule: admin OR (member AND NOT revoked), Rounded 4→4. |
| `CLASSIC_MANY_LUT_U64` | Rounded 16→8, inputs 0..8, two lanes with stride two. Compute grade=x/2 and flag=[x>=5], then code=2*grade+flag. |
| `CLASSIC_THRESHOLD_MVB_U64` | Rounded t_in=128, inputs 0..64; 17 threshold flags with Scaled t_out=2. |
| `CLASSIC_CBS_U64` | Rounded t_in=8, inputs 0..4; predicate F=[m>=2] selects an encrypted fee vector, then encrypted extras are added. Candidates use Scaled t_ring=8. |
| GLWE `CLASSIC_CBS_U64` with `input_encoding=MsbBoolean` | CBS input t=2, bits at 0/round(q_external/2); NOT selects encrypted service limits. Ordinary PBS messages remain unchanged. |
| `CLASSIC_ONE_HOT_U64` | NTRU only: t_in=8/M=4; generate the three nonzero NGSW selectors and perform four-way CMux over encrypted records at t_ring=8, with C0 as default. |

The exported `CLASSIC_*` presets use Classic blind rotation. The geometry below describes the presets before example overrides.

## Moduli, geometry and secret domains

| Symbol | Representation and value | Current use |
| --- | --- | --- |
| Q50 | `BarrettModulus<u64>`, 1125899906826241 | Default u64 NTT presets |
| Q54 | `BarrettModulus<u64>`, 18014398509404161 | GLWE NTT dual-modulus example and comparison fixtures |
| Q27 | `BarrettModulus<u32>`, 132120577 | u32 NTT dense PBS benchmark |
| Native32 / Native64 | `NativeModulus<u32/u64>`, implicit 2^32 / 2^64 | Fourier accumulator; also GLWE external modulus |
| q24 | `PowOf2Modulus<u32/u64>`, 2^24 | NTRU presets and Block ManyLUT examples |

These Barrett values fit `Q<2^(BITS-2)` and support the NTT lengths used here. Explicit powers of two use `PowOf2Modulus`; native moduli are implicit. Fourier TFHE uses Native accumulator moduli, including when NTRU's external LWE uses q24.

For the u64 configs, n denotes the small BR-control dimension in GLWE and the independent external dimension in NTRU. The GLWE presets below have rank k=1 and q=Q. The NTRU presets use q24 for the external LWE and a separate ring secret at Q.

| Family / presets | n / N | Small or external secret | Ring secret |
| --- | --- | --- | --- |
| GLWE classic PBS / Boolean | 866 / 2048 | Uniform binary | Uniform binary |
| GLWE ManyLUT / MVB | 728 / 1024 | Fixed-weight binary, h=32 | Sparse ternary |
| GLWE NTT classic CBS | 866 / 2048 | Uniform binary | Uniform binary |
| GLWE Fourier classic CBS | 800 / 1024 | Uniform binary | Uniform ternary |
| NTRU classic PBS / Boolean | 866 / 2048 | Uniform binary | Sparse ternary |
| NTRU ManyLUT / MVB | 728 / 1024 | Fixed-weight binary, h=32 | Sparse ternary |
| NTRU classic CBS | 800 / 1024 | Uniform binary | Sparse ternary |
| NTRU one-hot | 800 / 1024 | Fixed-weight binary, h=32 | Sparse ternary |

GLWE presets use `BootstrapKeyswitch` (BR→KS), except MVB, which uses `KeyswitchBootstrap` (KS→BR). The external LWE dimension is n in BR→KS and kN in KS→BR. Both orders return under their external secret. NTRU returns by coefficient Q→q switching, phase extraction and LWE KS. See [domain and return contracts](bootstrapping-contracts.md#ciphertext-domains-and-return).

`SparseTernary` samples (-1,0,+1) with probabilities (1/4,1/2,1/4). NTRU presets sample the ring secret f directly from this distribution and screen for backend invertibility and stability. The external LWE secret uses its own distribution.

## Block examples

These u64 examples set `BlindRotationMethod::Block` and use a contiguous `BlockBinary` secret for the BR controls.

| Example | n / N | Small or external q / ring Q | Block secret |
| --- | --- | --- | --- |
| [GLWE NTT `ntt_two_moduli`](../../crates/primus_tfhe_glwe_ntt/examples/ntt_two_moduli.rs) | 576 / 2048 | 1024 / Q54 | Small LWE, width 4, `AtMostOne` |
| [NTRU NTT ManyLUT](../../crates/primus_tfhe_ntru_ntt/examples/ntru_ntt_many_lut.rs) | 728 / 1024 | q24 / Q50 | External LWE, width 8, `ExactlyOne` |
| [NTRU Fourier ManyLUT](../../crates/primus_tfhe_ntru_fourier/examples/ntru_fourier_many_lut.rs) | 728 / 1024 | q24 / Native64 | External LWE, width 8, `ExactlyOne` |

The GLWE example defines its own rank-one config with a uniform binary ring secret. It chains two PBS calls at Rounded 4→4 in both PBS orders. The external LWE domain is (n,q) for BR→KS and (kN,Q) for KS→BR.

The NTRU examples override the method and external secret in `CLASSIC_MANY_LUT_U64`. Each of the 91 blocks contains one selected position, giving Hamming weight 91. See the [blind rotation support guide](../../crates/primus_tfhe/README.md#selecting-blind-rotation).

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

The GLWE NTT `CLASSIC_CBS_U64` uses q=Q50, rank one and independently sampled
binary secrets. Its padded t8 predicate `[m>=2]` was checked with a Scaled t8
CMux consumer and an LWE return. Other consumers need their own noise analysis.

| GLWE NTT Classic CBS role | Coefficient-unit σ | `(log₂B,L)` |
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
do not apply to the Fourier CBS fixtures.

## Decomposition by operation

A `DecompositionConfig` fixes `log_basis` and optionally `level_count`. With
`level_count: None`, preparation chooses `floor(value_bits/log_basis)` levels;
this can still discard low bits. An explicit count does not extend to fill the
modulus. See [decomposition precision](../../crates/primus_decompose/README.md).

The backend config sources above own BR, KS, trace, SS and output gadgets; output
gadget precision is distinct from the internal switching bases. Select precision
and projection before generating keys. Defaults are Ordinary/Separate; NTRU NTT
teaching CBS/one-hot presets explicitly use PairedTrace.
Fourier teaching presets remain Ordinary/Separate. The current [support matrix](bootstrapping-contracts.md#ntru-cbs-precision-and-projection-support)
also explains GLWE's separate trace-only Split35 context setting.

## Current backend benchmarks

The crate-local benchmarks use the exported presets or their own fixtures. Each row describes the timed request.

| Target | Configuration and timed request |
| --- | --- |
| `pbs` | Dense Classic u32/u64, one PBS of `F(x)=(3x+1) mod 16` at Rounded 32→32. |
| `many_lut` | All four backends use the unmodified `CLASSIC_MANY_LUT_U64` with Classic BR and h=32. Timing ends after one two-output PBS returns grade and flag. |
| `mvb` | `CLASSIC_THRESHOLD_MVB_U64`: one factorized request returning all 17 threshold flags. |
| `cbs` | `CLASSIC_CBS_U64` with predicate [m>=2], CMux over two nonconstant encrypted candidates at t_ring=8, and coefficient 1 returned as LWE. The GLWE NTT ID includes `n866_N2048` to separate the revised config from old n800/N1024 results. The `predicate_cmux_return` workload includes return cost. |
| GLWE `cbs_identity` | Benchmark-local G1 NTT and G2 Fourier comparison configs. Each padded or MSB bit is bootstrapped to a transform-domain GGSW. CMux validates the result before timing. Fourier ordinary/Split35 select the trace representation. |
| GLWE `modulus_domains` | Benchmark-local Classic BR with q=Q or q=1024, in both PBS orders, on NTT and TFHE-FFT. |
| `one_hot` | NTRU `CLASSIC_ONE_HOT_U64`: three nonzero NGSWs and four-way CMux at t_ring=8. |

Fourier benches select RustFFT, TFHE-FFT or both, using the same numerical config but engine-compatible material. Sources and commands: [GLWE NTT](../../crates/primus_tfhe_glwe_ntt/README.md#benchmarks), [GLWE Fourier](../../crates/primus_tfhe_glwe_fourier/README.md#benchmarks), [NTRU NTT](../../crates/primus_tfhe_ntru_ntt/README.md#benchmarks), [NTRU Fourier](../../crates/primus_tfhe_ntru_fourier/README.md#benchmarks).

The opt-in PBS Low/High, identity CBS and modulus-domain comparisons define their
parameters in their respective benchmark files. Use the [benchmark guide](testing.md#tfhe-benchmarks)
to select the cases and the [performance guide](../performance/README.md#tfhe-comparisons)
to interpret the comparison.

The dense PBS benchmarks provide explicit word-specific u32/u64 fixtures, rather
than casts of one config. Consult the bench-local geometry, secrets and noise
before comparing two timings.

## Evidence and changes to a workload

| Evidence | What it establishes |
| --- | --- |
| Config and constructor checks | Representable parameters, supported samplers, encoding/layout and applicable table/binding conditions; not actual secret identity or complete noise margins |
| Known-result checks in examples and benches | Sampled functional behavior when those workloads are run; not a coverage claim for every word, engine, secret or operation |

Changing message moduli, lane count, function, candidate range or chunk partition changes the error requirements even when existing keys remain compatible. Scaled MVB output is not automatically a valid Rounded PBS input. CBS predicates must be bit-valued for CMux, and arbitrary MVB factors can amplify noise far more than the threshold workload. Check the [operation's numerical contracts](bootstrapping-contracts.md) and [material pairing](composition.md#bind-material-before-evaluation).

A future security/DFR claim must specify its model and version, exact secret/sampler and conditioning assumptions, applicable functions, and complete error propagation including correlations. Finite historical diagnostics are not current validation; current checks and commands are described in the [testing guide](testing.md).
