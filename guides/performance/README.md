# Benchmark interpretation and performance choices

English | [简体中文](README.zh_CN.md)

Run the current benchmarks from the repository root. Use the [BFV/BGV commands](../development/testing.md#bfvbgv-工作流与基准) or the [TFHE commands](../development/testing.md#tfhe-benchmarks). Each crate owns its benchmark parameters and workload.

## Measuring a request

Keep the algorithm, inputs, parameters, compiler, features, CPU and actual
binary fixed for an A/B comparison. Separate setup, smoke checks and statistical
sampling. Decide whether encoding, encryption, output allocation, return to LWE
or result validation belongs to the measured request, and use the same boundary
for both variants. Compare individual-request latency and batch throughput
separately. Record requested heap, allocation traffic and process RSS as separate
quantities. Several historical runs pinned cores in two L3 groups of one Ryzen
9955HX3D. Their results describe that machine and workload.

## BFV and BGV

- **BFV multiplication.** Ordinary multiplication defaults to Exact, with
  HPSPOVERQ as an explicit choice. The integer schoolbook reference verifies
  the same tensor and scale-and-round result as Exact RNS NTT. A timing ratio
  against that reference only describes those two implementations. HPSPOVERQ
  has its own error terms. The temporary working-basis plan preserves the
  external ciphertext basis and selects internal bases with a finite
  circuit budget. Smaller working keys can lower total memory even when
  per-operation scratch grows. [Exact and HPSPOVERQ evaluation](../development/bfv-evaluation.md) · [Working-basis plan](../development/bfv-working-basis.md)
- **Evaluation keys.** Choose Radix or Hybrid independently of the BFV
  multiplication backend. For Hybrid, measure key setup, retained QP material,
  reusable scratch and the complete request. The evaluation-key P and BFV
  multiplication's computation-only P have different roles. [Native Hybrid keys](../development/native-hybrid-keys.md)
- **BGV leveled requests.** Include the actual correction-factor and prime-drop
  sequence in a comparison. Use the same logical inputs and check recovery
  after all required rotations, key changes and drops. [BGV evaluation](../development/bgv-evaluation.md#exact-prime-drop-and-logical-message-preservation)

## TFHE comparisons

Compare results at the same endpoint. Ordinary PBS benchmarks include the
configured return. The GLWE `cbs_identity` comparison ends at a consumable
transform-domain GSW. Its setup checks both input bits with a real depth-one
CMux before measuring. Include CMux and LWE return explicitly when those are
part of the workload. LightFHE G1 and CMUX2 derived profiles are local benchmark
fixtures with different input and consumer contracts from the teaching presets.
Historical cross-library PBS, CBS and EBS used different parameter profiles
and provide functional reference points. [Comparison commands](../development/testing.md#glwe-functional-comparison-benchmarks) · [Current benchmark parameters](../development/tfhe-parameters.md#current-backend-benchmarks)

Measure single-input and batched blind rotation separately. Retained sparse
schedules keep the encrypted selectors, dummy and arithmetic boundaries. Their
observed gains depend on geometry and workload. CBS with CMux and return needs
a complete measurement even when a scheme-switching kernel is faster or its
key payload is smaller. [Bootstrapping contracts](../development/bootstrapping-contracts.md)

## Fourier key generation

Fourier GLWE evaluation material is generated from native coefficient rows
before transformation. Regenerate material produced by the former unreduced
path and replace secrets whose affected material was disclosed. Use the exact
coefficient path for current GLWE Fourier timings. The historical repair
comparison measured setup separately and found higher
key-generation costs with mixed, much smaller online changes. The exact
native rows still incur Fourier conversion error and have backend-specific
precision limits. [Fourier error budget](../development/bootstrapping-contracts.md#glwe-fourier-error-budgets)

## NTRU projection

Choose the projection strategy before generating keys and preparing scratch.
NTT CBS performance presets use `PairedTrace`; the default configuration uses
`Separate`. Historical NTT results showed faster trace-plus-scheme-switch
projection with higher key and scratch costs than `Separate`. Compare the full
request and its error budget when selecting a strategy.
[Projection and precision contract](../development/bootstrapping-contracts.md#ntru-cbs-precision-and-projection-support)

## Historical evidence

The former experiment reports and data are available in Git at
`c0584af519270022cc704b500db72f3bdbb60cf4`. They identify the original source,
fixtures and measurement scope. Current benchmarks use the current source
and parameters. Security and decryption failure rates for current presets
require their own evidence.

```sh
git ls-tree -r --name-only c0584af5 -- guides/performance
git show c0584af5:guides/performance/bfv-multiplication.md
```
