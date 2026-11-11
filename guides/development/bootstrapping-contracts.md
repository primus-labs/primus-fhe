# Bootstrapping numerical contracts

Use the [operation guide](../../crates/primus_tfhe/README.md) to choose a workflow and the [parameter guide](tfhe-parameters.md) for experimental configurations. This guide connects the numerical conditions across compilation, blind rotation, CBS and one-hot selectors. Method-level layouts, checks and scratch contracts remain in rustdoc. These conditions do not provide a security estimate or failure-probability certificate.

All polynomial operations below use the negacyclic ring `R_Q = Z_Q[X]/(X^N+1)`. N is a supported power of two; q denotes the small BR-control LWE modulus and Q the accumulator modulus; the external GLWE-PBS domain depends on its order as described below. Native moduli mean `2^T::BITS`. Input/output plaintext moduli can differ. Error magnitudes use centered representatives; identities modulo Q alone are not real-valued noise bounds.

## Rotation geometry

For canonical x, define the ties-up quantizer

```text
R(x,q,L) = floor((x*L + floor(q/2))/q) mod L.
E_q(m)  = round(m*q/t_in) mod q.
```

Compilation uses `R(E_q(m),q,L)`, not `round(m*L/t_in)`. The two rounds can move a center: with N=32, q=5, t_in=3, m=1 and L=2N, encoding gives 2 and the center is 26; rounding the ideal fraction directly gives 21. See [rotation modulus switching](../../crates/primus_tfhe/src/rotation.rs).

For k interleaved outputs, let s be `next_power_of_two(k)` and H=N/s. Output j occupies coefficients `s*r+j`; each programmed input interval repeats its k encoded outputs followed by s-k zero lanes. H is the number of positions per output, not a repetition count for one message. Compilation places centers in 2H positions. It programs a front-half prefix of length `D<=ceil(t_in/2)` and appends the terminal center `min(R(E_q(D),q,2H),H)` carrying the negative of output zero's group. Each position takes the nearest center, ties going to the larger center; the remaining tail is not another valid input domain. All centers, including the terminal one, must increase strictly. `D<=H` is necessary capacity, not a noise-margin guarantee. See [front-half intervals](../../crates/primus_tfhe/src/lookup_table/compile/front_half.rs).

Execution instead quantizes each LWE coordinate at step s:

```text
R_s(x) = s*R(x,q,2N/s)
u_bar  = R_s(b) - sum_i R_s(a_i)*secret_i
ACC    = X^(-u_bar)*T.
```

Quantizing the decrypted phase once is not equivalent. Because s divides N, negacyclic wrapping preserves the output lane. The physical 2N must fit the coefficient word even for Native inputs. Ordinary PBS/MVB use step one; CBS/one-hot use their padded gadget width. Input error budgets must include encoding rounding and coordinate-wise quantization in addition to fresh encryption noise.

For an odd full domain `t_in=2h+1`, fold centers modulo N and negate upper-half outputs. The sorted input order is `0,h+1,1,h+2,...,h`; append N with `-F(0)`. Boundaries are `ceil((left+right)/2)`, and collisions of actual rounded centers are rejected. Typical spacing is N/t_in, about half the front-half spacing. This is a single-output entry; interleaved and bivariate compilation retain front-half contracts. See [odd-domain folding](../../crates/primus_tfhe/src/lookup_table/compile/odd_full_domain.rs).

## Ciphertext domains and return

| Path | Domain relationship |
| --- | --- |
| GLWE PBS | BR small LWE uses q; accumulator and ring KS use Q. BR→KS accepts/returns (s,q); KS→BR accepts/returns (S,Q), preparing its small BR input at q. |
| NTRU PBS and lookup | Independent external secret s at q and ring secret f at Q. Return performs coefficient-wise nearest Q→q rounding, signed phase extraction, then LWE KS at q. |
| Raw LUT compilation | Input q and coefficient Q can be independent; output encoding is a separate choice. |
| Bivariate LUT | Its constructor currently requires a common ciphertext modulus. |

For GLWE, let n be the small BR-control dimension and kN the flattened ring-secret dimension, with `n<=kN`. `BootstrapKeyswitch` accepts and returns the small-secret LWE: BR precedes ring KS at Q, compact extraction and Q→q rounding. `KeyswitchBootstrap` accepts and returns the flattened-ring-secret LWE: inverse extraction and ring KS at Q, compact extraction and Q→q rounding prepare the small input for BR, followed by full extraction. Equal ciphertext moduli do not make these external domains interchangeable.

Returning a phase rescales its existing centers; it does not recreate the output codec's centers. Include coefficient rounding multiplied by the extraction secret, KS error and encoding-scale mismatch in the output budget. For example, a Scaled output requires accounting for `(q/Q)*round(Q/t_out) - round(q/t_out)`. GLWE ManyLUT shares ring KS, then converts each compact extraction; NTRU ManyLUT shares the ring conversion across extracted outputs; MVB converts each factor product. See [GLWE orders](../../crates/primus_tfhe_glwe/README.md) and [NTRU returns](../../crates/primus_tfhe_ntru/README.md#ntrulwe-returns).

All configured noise standard deviations use coefficient units, including Fourier configurations. GLWE ring-KS rows use Q coefficient units and equal q/Q skips MS. BR and KS noise are independent choices; NTRU return KS uses q while BR uses Q. CBS trace/scheme-switch rows inherit accumulator encryption noise but have separate decompositions and error propagation. In GLWE KS→BR, fresh external LWE encryption uses the ring/BR noise setting, not KS-key noise. These sampler deviations describe fresh private-key encryption or individual key rows; public-key encryption includes additional public-key and combination errors. The [GLWE](../../crates/primus_tfhe_glwe/README.md#parameters-and-external-key-domain) and [NTRU](../../crates/primus_tfhe_ntru/README.md) family guides identify the configuration fields.

## Ternary and sparse rotation

Classic ternary represents a secret coordinate by mutually exclusive bits s_plus and s_minus. For its quantized mask exponent a, combine gadget controls as `G=Enc(s_plus)-X^(-a)*Enc(s_minus)`. Adding the external product of G with `(X^a-1)*ACC` implements rotation by `X^(a*(s_plus-s_minus))`. This saves an external product but retains both control ciphertexts' errors. NTT combination is exact in the field; Fourier adds its transform/conversion error.

Sparse BR uses a public map with c distinct bucket choices per input position and a private matching with at most one selected position per bucket. For bucket C_j,

```text
G_j = Dummy_j + sum_{i in C_j} X^a_i * Selector_(j,i).
```

The independently encrypted dummy represents one minus the sum of that bucket's selector bits. An unused bucket therefore targets the identity monomial, not zero. Encrypted zero selectors and the dummy still contribute noise. Under independent centered row errors of variance sigma², each coefficient of the aggregate row has variance `(|C_j|+1)*sigma²`; differing bucket sizes require an appropriate bound, not just their average. This local variance calculation does not establish the full BR tail distribution. Mapping and matching are defined in [sparse.rs](../../crates/primus_tfhe/src/sparse.rs).

Retrying the public map until matching succeeds conditions the published map on the fixed secret admitting a matching. It reduces generation failure without removing that correlation. Only the independent NTRU ring secret is conditioned on invertibility and, for Fourier, inverse stability; the external fixed-weight secret may have even weight. Conditioned secret/map distributions and evaluation-key KDM/circular-security assumptions require separate analysis. Matching, rejection sampling and inverse preparation have no constant-time guarantee.

GLWE NTT raw sparse and block BR also accept independent input batches. Their
four-lane workspaces share read-only key tiles on one thread; each lane retains
its own exponents, aggregate, accumulator and external-product scratch. Groups
of four and two use the same per-chain control order and arithmetic as single
calls; a one-input tail runs the original single kernel. Complete batch layouts
are checked before any output write, and evaluation allocates no memory. Outputs
remain separate coefficient-domain GLWE ciphertexts: summing, KS and extraction
belong to the caller. Shared physical key errors remain correlated between lanes.
See the [block workspace](../../crates/primus_tfhe_glwe_ntt/src/block/blind_rotation.rs)
and [sparse workspace](../../crates/primus_tfhe_glwe_ntt/src/sparse/blind_rotation.rs).

### Matching and error dependencies

For an independent initial map H, fixed-weight support S and matching event A,
ideal symmetric sampling gives `P(H|S,accepted)=P(H) 1[A(S,H)]/p`, with p
support-invariant. The marginal support stays uniform, but the accepted map and
support are correlated. The retry cap changes generation failure, not this
conditional law; measured log₂(1/p) is not a certified security loss.

For GLWE phase `phi_S(a,b)=b-a*S`, bucket monomial M and residual
`R=C-Reconstruct(D)`, the exact update is
`phi_S(C_next)=M*phi_S(C)-M*phi_S(R)+sum D*E`.
All encrypted-zero selectors and dummies contribute E. With secret norm S1,
residual bounds epsilon and row bound Emax, a conservative BR error bound is
`B*epsilon_BR*(1+S1)+(r*n+B)*Emax*(k+1)*L_BR*N*beta_BR/2`;
ring KS adds `epsilon_KS*S1+Emax*k*L_KS*N*beta_KS/2`.
These support bounds are generally too loose to choose practical parameters.

A fresh-row conditional MGF argument needs an input independent of evaluation-key
errors, predictable digits, and the actual sampler's mean/support. With independent
ideal RNG words, centered rows and rho=q/Q, Hoeffding's variance proxy is
`rho²*Emax²*((r*n+B)*(k+1)*L_BR*N*(beta_BR/2)²+k*L_KS*N*(beta_KS/2)²)`.
Subtract any digit-weighted sampler drift from the usable radius; shared sign/magnitude
words need not give an exactly zero mean. This does not prove fixed-key,
adaptive/feedback-request tails, accepted-map security or CBS consumption.
Historical PBS-success/CBS-failure cases show why the output gadget and subsequent
CMux need their own budget; fewer BR rows alone are not a usable CBS preset.

## NTRU first lifting

Write the NTRU phase as `f*C = message + error`. NLEV[mu] has rows with phase `g_l*mu + e_l`; NGSW[mu] has rows targeting `g_l*f*mu`. For gadget decomposition define

```text
epsilon(P) = P - sum_l g_l*D_l(P).
```

Classic BR starts from the public polynomial `P=T*X^(-b)` with quantized b, and fuses lifting with coordinate zero:

```text
K = I + (X^a-1)*B_plus + (X^(-a)-1)*B_minus
C = sum_l D_l(P)*K_l.
```

I is NLEV[1], the B controls are NLEV secret bits, and binary omits B_minus. K targets `H=X^(a*secret_0)`, so the phase is `P*H - epsilon(P)*H + sum_l D_l(P)*e_l(K)`. Only P is approximately decomposed: a small monomial difference is not discarded by that decomposition. If a=0, K=I still performs the required lift.

Sparse and Block BR use their first whole group's NLEV aggregate K_0 instead. The same phase formula holds with H equal to the selected monomial, or one for an unoccupied bucket. Even an empty first group lifts through its encrypted dummy. Later coordinates/buckets use NGSW on encrypted accumulators; NGSW's extra f factor prevents substituting it for this public-polynomial lift. MVB, CBS and one-hot use the same BR initialization. See the [NTRU family](../../crates/primus_tfhe_ntru/README.md#sparse-coefficient-keys).

## Ordinary CBS and consumption

Padded CBS programs a front-half Rounded input domain with gadget-scaled values `g_l*F(m)`, projects the resulting coefficients into GLev/NLev rows, and can scheme-switch to GGSW/NGSW. The result remains under the accumulator secret, without an ordinary output message codec or LWE return. GLWE KS→BR still performs input KS before this flow. The ManyLUT accumulator may have a nonzero message tail, so prefix expansion requiring a zero tail cannot replace its projections.

GLWE CBS also supports explicit MSB Boolean input, encoded at 0 and round(q/2). It uses a centered sign LUT: with stride p and gadget scalar g, each lane contains −h on [0,N/2) and +h on [N/2,N), where 2h=g(F(1)−F(0)) modulo Q. Add gF(0)+h to the projected GLWE body constant **after full reverse trace**, before scheme switching. Odd Q uses modular halves; even/native Q requires even gadget weights. The cut N/2 must align with p. The strict protection condition is signed |E−mN|<N/2 modulo 2N, for the actual separately quantized exponent E above, not just a rounded plaintext phase. Input KS/MS, encoding rounding and coordinate-wise rounding count toward that condition. Native trace halving is not linear, so moving this offset before trace changes its rounding error.

The compiled [CBS program](../../crates/primus_tfhe/src/lookup_table/circuit_bootstrap.rs) binds encoding, geometry, weights and offsets; GLWE `cbs_encryptor` uses that operation's input mode while ordinary PBS clients retain their own encoding. NTRU accepts padded programs only: adding a public constant to an NTRU ciphertext would change its phase by that constant times f, unlike adding to a GLWE body.

For CMux consumption, F must be bit-valued over the entire programmed domain. Candidate ciphertexts must share the accumulator secret, modulus and encoding. Matching output lengths does not establish that BR decomposition resolves the LUT's smallest gadget scale or that the resulting control's noise fits its consumer. See [CBS compilation and consumption](../../crates/primus_tfhe/README.md#cbs-output-and-consumption).

NTRU scheme-switch material binds the complete output basis. GLWE material binds output layout and supports a different output basis only through the evaluator's checked compatibility entry. Neither check proves actual secret or transform identity. See [GLWE CBS](../../crates/primus_tfhe_glwe/README.md#boolean-and-cbs) and [NTRU CBS](../../crates/primus_tfhe_ntru/README.md#cbs-and-examples).

Rank-one GLWE NTT scheme switching uses only `GLev(s²)`: with phase `b−as`, its mask row is `sum D(a)GLev(s²)+(b,0)` and its body row retains the input. The exact correction uses the final body, including any post-trace offset. Compared with a full `GGSW(-s)` product, this removes body decomposition and its key-error terms, while retaining shared input error multiplied by `−s` and square-secret decomposition residuals. It does not imply lower error for every input or an independently sampled body error. Higher ranks and Fourier retain full products. The implementation and boundary contract belong to [`NttGlweSchemeSwitchKey`](../../crates/primus_glwe/src/scheme_switch/ntt.rs).

### GLWE Fourier error budgets

[Exact coefficient key generation](../performance/README.md#fourier-key-generation) does
not make stored Fourier rows or online products exact. Keep sampling error,
decomposition residuals, native floor corrections and floating-point error
separate. Bounds depend on the actual engine, plan, tables and operand ranges;
a roundtrip test or observed maximum is not a forward/inverse error bound.

Full Fourier SS returns frequency-domain GGSW rows without an inverse transform
or integer rounding. Its projection errors are shared across mask/body rows.
When CMux consumes the control, combine each lane's source weights as
`W_l=d_body,l-sum_i d_mask,i,l*s_i` before estimating its error. Propagate stored
spectrum errors once, including their cross terms with consumer digit-transform
errors. Retain component-wise spectrum bounds for these terms; a phase bound
alone is insufficient. Add inverse-transform and integer-recovery error where
the consumer actually performs them, not at an artificial SS recovery boundary.

GLWE Split35 affects trace only. Low 35 bits and high 29 bits come from the same
exact native row, use the same `2^-64` torus scale and share digit transforms.
Recover each limb separately before wrapping reconstruction. Their integer
error radii combine as `E_low+2^35*E_high`; one high-limb error is amplified by
`2^35`. Do not assume independent limbs or round their combined real error only
once. Split35 does not cover ordinary BR, SS, CMux or client decryption, nor does
it remove the [native floor corrections](#normalized-reverse-trace).

Budget the actual input KS/MS, candidate ciphertexts and return path. Full-ring
Fourier client decryption adds its own transforms, products and recovery error;
an integer LWE decoder does not. Count the positions actually decoded, rather
than GGSW rows. Under a common condition G, a full-request bound needs valid
input/decoder event bounds and `P[not G]`; a union bound does not require
independence but cannot supply missing bounds. Unknown FFT envelopes or shared
source tails remain unknown. Conditional estimates or finite successful tests
alone do not certify full-request DFR (decryption failure rate) or security cost.

## Normalized reverse trace

Let `N=2^ell`, `sigma_d(P)=P(X^d)` and let `Pi_r` retain coefficients at positions divisible by N/r, for `r=2^h`. Reverse trace visits degrees `d_k=2^k+1` in ascending order, k=h+1,...,ell: halve the current coefficient ciphertext, apply automorphism with key switching, then add the two results. It preserves ring size. Full trace has r=1; r=N copies the input.

For odd Q, `H_k=(I+sigma_dk)/2` uses the modular inverse of two and satisfies

```text
H_ell ... H_(k+1) = Pi_(2^k).
Phi(output) = Pi_r(Phi(input)) + sum_{k=h+1}^{ell} Pi_(2^k)(e_k).
```

Here Phi is the phase under the original secret and e_k is the actual automorphism/KS phase error after halving, including approximate decomposition. The identity follows by eliminating unwanted coefficient positions from the highest degree downward. It describes the completed suffix, not independent real-valued divisions of each intermediate error by two, and it does not make approximate key switching linear. Late e_k can remain outside the target coefficients.

| Backend | Halving and its numerical domain |
| --- | --- |
| NTT | Canonical residues multiplied by `2^-1 mod Q`; the current path requires odd Q below `2^(T::BITS-1)`. This is not rounded integer division and does not inherit native-torus noise bounds. |
| Fourier | Unsigned `floor(c/2)` on each canonical coefficient, including wrapped negative representatives, before automorphism. Complex Fourier values are never divided by two. |

For native `Q=2^w`, define p_k from the parity of the **actual current ciphertext**, before that step's halving. Since `2*floor(C/2)=C-p`, its phase correction is `rho_k=f*p_k` for NTRU and `rho_k=p_b-sum_j p_aj*s_j` for GLWE. After completing the suffix, the exact modular identity is

```text
Phi(output) = Pi_r(Phi(input))
            - sum_{k=h+1}^{ell} Pi_(2^(k-1))(rho_k)
            + sum_{k=h+1}^{ell} Pi_(2^k)(e_k).
```

Half-modulus lift ambiguities cancel in the completed suffix; e_k includes actual FFT/conversion and KS errors. Do not move floor-halving across addition or signed monomial shifts, or reuse parity from a differently scheduled ciphertext. Each rho term has coefficient bound `||f||_1` for NTRU or `1+sum_j ||s_j||_1` for GLWE. If the actual e_k have bounds B_k, the introduced contribution is bounded by `sum B_k` for odd Q, or `sum B_k+(ell-h)*rho_bound` for native Q. Include the projected input error separately. These are conditional deterministic bounds, not Gaussian variance or tail estimates; parity need not be independent or unbiased.

To project coefficient i, first use `X^-i*C` and then full reverse trace. Reduce i modulo 2N: indices at least N carry the negacyclic minus sign and cannot simply be reduced modulo N. Ordinary CBS uses i=l; one-hot selector j uses i=l-j*S modulo 2N, with S=N/M. This does not add a factor N or change the gadget scalar. Arbitrary message tails are allowed. Prefix expansion yields independent constants only when the target message is zero outside that prefix; fewer requested outputs do not establish that premise, nor does a message zero tail imply zero ciphertext/noise tails.

Outputs share BR and evaluation-key errors. Fourier PairedTrace one-hot NGSW batches also share the first pair across targets, introducing further correlations. Do not combine selector/level errors by root-sum-of-squares without additional assumptions. Bound all coefficients needed by subsequent scheme switching, CMux and rotation, not only the projected constant.

### NTRU CBS precision and projection support

`CbsConfig.fourier_precision` chooses BR, trace and SS precision independently;
`CbsConfig.projection` chooses the NGSW-only projection schedule. Configure both
before preparing the context and keys. Defaults are all `Ordinary` and `Separate`.
NTRU NTT teaching CBS/one-hot presets explicitly select `PairedTrace`. Fourier
backend teaching presets retain `Separate` and ordinary precision.

The matrix describes production NTRU CBS and one-hot support. Binary includes
fixed-weight binary; sparse BR requires a fixed-weight binary input secret.
Both RustFFT and TFHE-FFT have the same supported combinations.

| Backend / ring word | BR algorithm | BR precision | Trace / SS precision | Projection | Outputs |
| --- | --- | --- | --- | --- | --- |
| NTT, u32/u64 | Classic binary/ternary, sparse binary, block binary | `Ordinary` config marker | `Ordinary` config markers | All four strategies | NLEV, NGSW, dual |
| Fourier, native u32 | Classic binary/ternary, sparse binary | Ordinary | Ordinary / Ordinary | Separate | NLEV, NGSW, dual |
| Fourier, native u64 | Classic binary/ternary, sparse binary, block binary | Ordinary | Independently Ordinary or Split | Separate | NLEV, NGSW, dual |
| Fourier, native u64 | Classic binary, block binary | Split | Independently Ordinary or Split | Separate | NLEV, NGSW, dual |
| Fourier, native u64 | Classic binary/ternary, sparse binary, block binary | Ordinary | Split / Split | FusedLastStage or PairedTrace | NGSW fused; NLEV/dual separate |
| Fourier, native u64 | Classic binary, block binary | Split | Split / Split | FusedLastStage or PairedTrace | NGSW fused; NLEV/dual separate |

The four NTT strategies are `Separate`, `FusedLastStage`, `FusedLastThreeStages`
and `PairedTrace`. NTT arithmetic does not use FFT precision; its context rejects
non-Ordinary markers. Fourier rejects `FusedLastThreeStages`, fusion without
split trace and SS, split u32, and split ternary/sparse BR. It does not silently
fall back. Fourier ring Q is native; the external LWE modulus is independently chosen.
Each row still requires the usual shape, secret-distribution, gadget and input
guard contracts. NLEV-only and dual outputs always execute separate trace/SS,
**with their configured precision**, even when a fused strategy is selected.

For split, a canonical native u64 coefficient is split at `b=low_bits` into
low b bits and high 64−b bits. `0<b<64` and the constructor's product-range bound
protect representation and inverse conversion, not FFT accuracy. Trace and SS
widths may differ; changing b, N, decomposition or branch count requires
rebudgeting low-limb error and high-limb rounding failure,
which is amplified by `2^b`. Successful tests do not establish a security or
full-request decryption-failure bound. Small-ring unequal-width tests are not
large-parameter recommendations.

Both ordinary and split key generation form exact native coefficient rows.
Ordinary material transforms complete rows once. Sparse and block BR retain
coefficient rows and aggregate them in the native ring before the selected
transform. Split Block BR extracts canonical limbs after aggregation, including
negacyclic signs and wrapping carries. Its workspace holds only the selected
aggregate spectra and reuses product scratch for limb conversion. Block and
split require u64. Ordinary classic and sparse BR support u32 and u64.
Only the selected representation is stored. Conversion precision still
determines the represented error. SS reconstructs coefficients before returning ordinary
Fourier NGSW controls; BR-internal CMux follows the BR precision. Consumer
operations need their own precision budget.

Fused residuals differ from Separate, so the binary per-stage recurrence cannot
be reused unchanged. See [`NttNtruProjectionKey`](../../crates/primus_ntru/src/scheme_switch/projection.rs)
and the [Fourier projection key](../../crates/primus_tfhe_ntru_fourier/src/circuit_bootstrap/key.rs)
for pair/terminal phase equations, key-message assumptions and scratch ownership.
Fusion need not reduce total noise. PairedTrace's Fourier one-hot NGSW multi-target
path shares the first pair; ordinary CBS, single-target, NLEV/dual and NTT paths
retain their own schedules. Its extra 4N-word cache belongs to the one-hot
evaluator. See [projection performance tradeoffs](../performance/README.md#ntru-projection).
GLWE does not expose these NTRU projection choices. Its
`CbsConfig::fourier_trace_precision` selects Ordinary or Split35 and is retained
by `CbsParameters`. Split35 requires the Fourier backend feature `split-trace`,
native u64, rank one and a ring secret sampler bounded by one; Ordinary retains
the existing word-width/rank support. The choice affects only trace material;
BR, SS and PBS key switching
remain ordinary Fourier. Evaluators obtain matching scratch from the actual key.
There is no GLWE trace/SS fusion or paired-trace configuration. See the
[context contract](../../crates/primus_tfhe_glwe_fourier/src/context.rs).

Paired Fourier trace uses unsigned `floor(c/4)` per prefix pair, followed by
one SS-basis `floor(c/R)` with R=4 (even log₂N) or R=8 (odd log₂N). It shares
digit FFTs and restores branch permutations after the inner products. Native
integer lifts must be retained through later divisions; modular phase identities
alone do not justify dropping wrap terms. The key's [rustdoc](../../crates/primus_tfhe_ntru_fourier/src/circuit_bootstrap/key.rs)
owns the pair/terminal equations and scratch contract. Neither paired trace nor
terminal fusion establishes independence of shared-key errors across selectors.

For the native Fourier terminal, let gamma=sigma_(N+1), Pi2 retain even
coefficients, a=floor(c/2), r=c-2a, and a=sum(g_j*d_j)+epsilon using the SS
basis. With identity/cross key phases g_j*f²+eta_id,j and
g_j*f*gamma(f)+eta_cross,j, respectively, the exact fused phase is
`f*Pi2(f*c) - f*Pi2(f*r) - 2*f*Pi2(f*epsilon)
 + sum(d_j*eta_id,j + gamma(d_j)*eta_cross,j)`.
The cross key encrypts gamma(f), not f*gamma(f). Inverse-permute its split
limbs offline; sum each branch's frequency inner products before restoring its
permutation. Low/high inverse rounding remains separate, followed by native
wrapping reconstruction and an ordinary output FFT. Add the actual
`f*(E_low + 2^b*E_high + E_output)` error; fusion does not eliminate floor bias,
key correlations, or the ordinary output's precision limit. The NLEV/dual path
retains the complete trace key and separate SS. These equations require a new
noise budget; successful consumer tests are not a failure-probability bound.

Method-level contracts remain on NTRU [NTT](../../crates/primus_ntru/src/trace/ntt.rs) / [Fourier](../../crates/primus_ntru/src/trace/fourier.rs) and GLWE [NTT](../../crates/primus_glwe/src/trace/ntt_operations.rs) / [Fourier](../../crates/primus_glwe/src/trace/fourier_operations.rs) trace.

## One-hot CBS

Let the chunk radix be `M=2^tau`, with input message modulus t=2M. Input m uses unsigned Rounded encoding `round(q*m/(2M))`. If L is the output gadget level count, set `W=next_power_of_two(L)`, `S=N/M` and `A=N/(2MW)`; require `2MW<=N`. Padding levels are zero. The test polynomial is

```text
T = sum_{j=1-A}^{A} sum_{l=0}^{L-1} g_l*X^(l-jW).
```

BR quantization uses step W, not MW. If its actual quantized phase satisfies `u_bar=S*m+W*e mod 2N` with `-A<=e<A`, negative BR followed by `X^(rS-l)` and full normalized reverse trace targets `g_l*delta_r(m)`. The guard is left-closed/right-open: a midpoint belongs to the larger message. e includes input encryption, encoding and coordinate-quantization errors. N and gadget capacity checks cannot prove this guard. See [OneHotLookupTable](../../crates/primus_tfhe_ntru/src/one_hot.rs).

NLEV→NGSW scheme switching preserves the complete output basis and adds f/f²-dependent errors; see [CBS parameters](../../crates/primus_tfhe_ntru/src/circuit_bootstrap.rs). Budget them at the smallest output gadget scale and at the eventual consumer.

Full one-hot APIs produce all M coefficient NLEVs or transformed NGSWs. Compact NGSW APIs omit branch zero for consumers of the form `C0 + sum_{r>0} delta_r*(Cr-C0)`. They skip its projection/scheme switch, not shared BR, and do not widen the guard. The fused consumer sums all external-product errors; sequential CMux estimates cannot simply be reused. Fourier rounds after the sum, so ciphertext coefficients can differ from separately converted products.

## Factorized MVB

In the integer negacyclic ring, `S=1+X+...+X^(N-1)` satisfies `(1-X)*S=2`. For an unscaled integer LUT p_i, form `W_i=(1-X)*p_i`: its first coefficient is `p_i[0]+p_i[N-1]`, and later coefficients are `p_i[j]-p_i[j-1]`. With actual Scaled output scale Delta, `V=(Delta/2)*S` gives `V*W_i=Delta*p_i`.

Odd Q uses the modular inverse of two; Native Q requires an even actual Delta and integer halving. This construction halves noiseless V, not a noisy ciphertext. Never reduce W_i modulo the plaintext modulus. Fourier transforms signed integer factors without torus scaling. See [FactorizedLookupTable](../../crates/primus_tfhe/src/lookup_table/factorized.rs).

All outputs share the initialization/BR error e_BR. A deterministic bound is `||W_i*e_BR||_infinity <= ||W_i||_1*||e_BR||_infinity`. Outputs are correlated; independent-coefficient variance estimates need additional assumptions. GLWE BR→KS adds output KS error after multiplication; KS→BR switches the input once before BR. NTRU factors amplify both first-lift and BR errors before each Q→q/extraction/KS return.

At the final ciphertext modulus q, let Delta be the decoder's scale and `epsilon=t_out*Delta-q`. For decoded message y and integer phase error e relative to `Delta*y`, a sufficient condition is `|epsilon*y+t_out*e|<q/2`; input rotation margins remain a separate requirement. Scaled numeric flags are not automatically Boolean gate inputs or Rounded feedback ciphertexts. Prefer ManyLUT when capacity and margins suffice; MVB needs suitable factor norms and its own transform/error budget.
