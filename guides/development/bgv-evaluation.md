# Native BGV evaluation and prefix levels

[Library guide](README.md) · [BGV workflow](../../crates/primus_bgv/README.md)
· [Representation boundaries](rns-phase-conventions.md)

The fixed-u64 rank-one backend uses `R_Q=Z_Q[X]/(X^N+1)`, native `[c0,c1]`,
and phase `c0+c1*s=lift(m)+p*e`. Every q_i is 1 modulo p. Equations below are
negacyclic polynomial identities; evaluating them in one agreed NTT convention
does not change their signs. Actual secret identity, canonical ciphertext
residues and transform identity remain caller contracts after numerical checks.

## Tensor and degree lifecycle

Ordinary requests prepare `BgvMultiplication::try_new(context,&relinearization_key)`.
The operation derives the actual level from the key and owns reusable quadratic
and relinearization scratch. `multiply_to` and `square_to` write ordinary
degree-one ciphertexts; `square_assign` overwrites one input after its tensor
has been retained internally. This prepared request is allocation-free and does
not require the caller to manage an intermediate degree-two buffer. Public and
private encryptors also provide allocating `encrypt`/`encrypt_centered` methods;
prepared `*_to` entries retain explicit output reuse.

The advanced split lifecycle remains available for callers that need its actual
unscaled quadratic intermediate:

`BgvEvaluator::mul_to` writes `[c0*d0,c0*d1+c1*d0,c1*d1]`; `square_to` uses
`[c0²,2*c0*c1,c1²]`. Their phase is the product of the input phases. This is
ordinary multiplication in R_Q, with no BFV scale-and-round. If integer message
lifts satisfy `u*v=m_out+p*k`, the intended product error is
`k+u*e_v+v*e_u+p*e_u*e_v`. Message carry belongs in the noise analysis.

`BgvQuadraticCiphertext` represents `t0+t1*s+t2*s²`, not two independent secrets.
Its current consumer is relinearization. Linear/automorphism/prime-drop/recovery
APIs accept degree-one ciphertexts, making the degree transition explicit.
The backend does not silently reduce an unrelinearized tensor as rank-two GLWE.

## Why division by p precedes gadget decomposition

This section describes the signed-radix Q backend. Hybrid uses a separate QP
identity and does not preprocess its input by p^-1; see below.

Let h be the source secret, σ(s), or s². At one modulus level, evaluation-key
columns K_j have native phase `p*g_j*h+p*e_j`. Let

```text
x = a*p^-1 mod Q,
D(x) = sum_j d_j*g_j,
r = center_Q(x-D(x) mod Q).
```

Here p^-1 is a **modular inverse**, not integer floor division. The existing
multi-limb signed decomposition gives digits `-B/2 <= d_j < B/2`, with actual
weights `2^drop_bits*B^j`; its documented circular residual bound applies to r.
Then the componentwise gadget product P has phase

```text
phase(P) = a*h + p*(sum_j d_j*e_j - r*h) mod Q.
```

The key noise and the discarded residual both preserve the p-multiple form.
For a bound, include `p*sum_j ||d_j*e_j||_infinity` and `p*||r*h||_infinity`;
all products are full-ring convolutions. A simple sufficient convolution bound
is `||u*v||_infinity <= ||u||_1*||v||_infinity`. The resulting intended phase
must still fit centered Q. A modular p-multiple alone is not a no-wrap guarantee.

The three role operations combine P as follows:

| Operation | Decomposed component a | h | Native result |
| --- | --- | --- | --- |
| Source-to-target key switch | c1 | s_source | `[c0+P0,P1]` under s_target |
| Automorphism X→X^k | σ(c1) | σ(s) | `[σ(c0)+P0,P1]` under s |
| Relinearization | t2 | s² | `[t0+P0,t1+P1]` under s |

Omitting p^-1, omitting p from key weights, or using an ordinary approximate
GLWE key changes this equation. For example, Q97,p3,radix4 with three retained
weights [2,8,32] reconstructs a=1 as D(a)=2; ordinary truncated switching can
therefore change the plaintext even with zero key error. Decomposing a*p^-1
instead gives the p-preserving residual identity.

`DecompositionConfig::level_count=None` means the maximum available digit count,
not necessarily zero residual. Q's bit width need not be divisible by log_basis.
Each key privately owns its actual basis and columns. Radix Q/weights/drop bits
change at lower levels. The API binds keys to their actual level; slicing a
matrix is not a supported constructor for a new radix or Hybrid key. The distinct
role types prevent passing a key with the wrong semantic role; binding checks its
local context, N,p,ordered Q and level index. That relation does not authenticate
same-context actual secrets or the mathematical provenance of raw imported data.

`BgvRelinearizer::try_new(context,key)`, `BgvKeySwitcher::try_new(context,key)`
and `BgvAutomorphism::try_new(context,key)` derive the level from the key, just
like `BgvMultiplication`. The key must belong to that context and its actual level
must be prepared. Key generation, linear evaluators and modulus switching still
select an explicit level. Context-created ciphertexts and their views retain the
context/level; `client.decrypt(ciphertext)` / `decrypt_to(ciphertext,output)` use
it directly. Advanced raw recovery uses `decrypt_at_level` / `decrypt_at_level_to`.
See [context binding and raw interoperability](scheme-context-binding.md) for
checked adoption and the remaining same-secret/NTT caller contracts.

With `batching`, use `context.batching_encoder()` for full-ring slots without
repeating N/p. A smaller encoder remains an explicit advanced choice.
`client.row_rotation_key(level,&encoder,steps,config,rng)` uses signed row-left
steps modulo the row length, while `row_swap_key(level,&encoder,config,rng)`
exchanges rows. They validate the encoder's p and capacity before sampling and
return the existing automorphism-key type. The encoder's exponent algorithm,
native key generation and prepared operation are shared with the explicit
`automorphism_key` entry; no extra table or operation owner is retained.

## Native Hybrid keys

Prepare `context.hybrid_key_parameters(level,decomposition_count,&key_p)` and
pass its shared `Arc` to ordinary or collective role-key generation. The actual
key domain is QP, while ciphertexts remain in Q and native plus phase. Columns
have phase `P*projector_j*h+p*e_j`; input digits are partitioned Q residues, with
no radix p^-1 preprocessing. After QP accumulation, subtract p times the exact
centered P lift of `p^-1*T_P`, then multiply by `P^-1` in Q. The resulting error
remains a p multiple, including the component corrections.

The [native Hybrid contract](native-hybrid-keys.md) derives the exact identity,
digit/key/ModDown bounds, fixed full-chain partitions and source-secret recovery
from its actual highest Q. It also distinguishes key P from multiplication-only
bases and describes QP collective linear/S² contributions. Choosing a key backend
does not establish security, complete noise or a valid recovery/drop schedule.

## Exact plaintext-preserving prime drop

Let q be the last prime, Q'=Q/q and x any coefficient lift of a component.
Choose `r=center_q((x mod q)*p^-1 mod q)`. The map is

```text
F_q(x) = (x-p*r)/q mod Q'.
```

The numerator is exactly divisible by q. Its integer quotient is congruent to
x modulo p because q≡1 modulo p. Replacing x by x+kQ only adds kQ' to the
output; canonical and centered input lifts therefore give the same Q' residue.
This is nearest division constrained to the required plaintext congruence,
not BFV's ordinary nearest rounding. No correction factor is necessary within
the supported family; general-prime chains remain rejected.

Only the discarded limb needs an INTT. Compute its inverse-p centered residue,
lift it into each retained modulus, multiply by p there, transform that correction,
subtract from the retained NTT input, and multiply by q^-1. The potentially wide
integer p*r is never formed in u64. Total Q is never reconstructed on this path.

For native phase z=m+p*e, let component remainders be r0,r1. The intended new
phase is `z'=(z-p*(r0+r1*s))/q`, modulo Q'. In particular,

```text
e' = e/q - (r0+r1*s)/q + (1/q-1)*m/p.
```

The total is an integer; fractional terms are a noise-analysis identity, not a
floating-point implementation. A conservative phase bound includes
`||z||_infinity/q + p*(q-1)/(2*q)*(1+||s||_1)`. Require this intended new phase
to lie in (-Q'/2,Q'/2) before applying centered recovery. Reduction by Q' can
otherwise change its message modulo p. Apply a complete bound at every level.

For consecutive supported odd divisors a,b, the centered correction sum obeys
`(a-1)/2+a*(b-1)/2=(a*b-1)/2`; inverse-p residues give
`F_b(F_a(x))=F_(a*b)(x)` modulo the final prefix. Independent tests compare the
actual component quotients with arbitrary-width integer arithmetic, including
canonical/centered boundaries, p2/p254 and 150-bit Q.

## Public static circuit budgets

`BgvParameterRequest::create_context` generates validated NTT primes from explicit
N, p, prime width/count, levels and secret/error laws. Q primes are searched in
the intersection `q=1 mod 2N` and `q=1 mod p`, including composite coefficient p.
Generation and `BgvCircuitPlan::try_new` are separate: the latter validates all
actual caller-selected Q/key-P primes and admits a topologically ordered ordinary
static circuit. It is a bounded resource/admission workflow, not a search for an
optimal Q or an automatic security certificate. A rejection identifies the first
node, its actual prefix level, phase bound, capacity and required Q bit width.

The budget tracks an intended integer phase z congruent to the ciphertext phase
modulo the actual Q, and `Z >= ||z||_infinity`. At every node it checks
`Z <= floor(Q/2)`, equivalently `2Z<Q` for odd Q. The recorded error envelope
relative to the centered output message is `floor((Z+floor(p/2))/p)`.
This keeps message carries in tensor/plaintext operations instead of silently
replacing each integer product by a reduced message with zero carry.

Let E be the actual error sampler's maximum magnitude, B_s the secret sampler's
hard coefficient support, and H=N*B_s. These supports include Gaussian truncation
as implemented; no independence, standard-deviation heuristic or tail-event
estimate is used. Public encryption's ephemeral is always CBD1, even when the
actual secret is Gaussian or follows another supported law. Full-range message
lift M is `floor(p/2)` for centered and `p-1` for unsigned embedding.

| Node | Sufficient full integer-phase bound |
| --- | --- |
| Fresh private | `M+p*E` |
| Fresh public | `M+p*(N*E+E+H*E)` from `e_pk*r+e0+e1*s` |
| Ciphertext add | `Z_left+Z_right`, at one level and under the same actual secret |
| Add public plaintext a | `Z+||lift(a)||_infinity` |
| Multiply public plaintext a | `||lift(a)||_1*Z` |
| Tensor plus relin | `N*Z_left*Z_right` plus the actual relin-key terms below |
| Automorphism | `Z` plus the actual automorphism-key terms |
| Source-to-target switch | `Z` plus the actual switching-key terms |
| Drop last q | `ceil(Z/q)+ceil(p*(q-1)*(1+H)/(2q))` |

Public plaintext norms are scanned from the same canonical polynomial and lift
passed to evaluation, so dense coefficients, sparse scalars and encoded slots
retain their actual public norm. Reusing those norms for a different, larger
plaintext violates the declared circuit contract. `Multiply` includes ordinary
relinearization; using equal operand indices represents squaring. The bounds
cover correlated inputs and reusing one actual role key across nodes.

For signed radix B with L actual retained digits and circular residual R, the
added phase contributions are `p*N*L*(B/2)*E` and `p*R*H_source`. The role norm
is H for source switching/automorphism and H² for relinearization. The planner
uses the actual level's prepared decomposition, including nonzero residual even
when `level_count=None`. For Hybrid, let `Q_j` be the product in actual partition
I_j and `A=N*sum_j(|I_j|*Q_j*E)`. It records
`ceil(p*A/P)` plus `ceil(p*(P-1)*(1+H)/(2P))`. These follow the QP/centered
ModDown identities above; it does not insert the radix branch's p^-1 preprocessor.
The separate integer ceilings intentionally give a conservative sufficient bound.

`plan.key_config(level)` returns the actual prepared Radix/Hybrid configuration
used by these formulas. Pass it to the ordinary role-key generators rather than
creating a different backend or smaller P. The plan borrows context and owns only
public diagnostics and used numerical key configurations; it does not retain
clients, secret observations or ciphertext scratch. Per-step terms sum to the
reported full phase, and the exact remaining margin is `floor(Q/2)-Z`.

The first security input records data Q; additional inputs record each actually
used Hybrid key-level QP domain with the actual secret/error laws. Multiplying a
BGV zero-encryption sample by p^-1 modulo its coprime modulus gives the unscaled
error law recorded for RLWE attack estimation. Successful admission leaves these
inputs `NotEvaluated`; a separate estimator result and correlated/circular-key
assumptions remain necessary. This budget excludes collective/raw/SSLE keys,
privacy flooding/openings, arbitrary imported secrets and arbitrary programs.
It does not relax q_i=1 modulo p or introduce general-chain correction factors.

The [leveled coefficient example](../../crates/primus_bgv/examples/leveled_coefficients.rs)
consumes this plan for `(a*b)^2`, two prime drops, an automorphism, source-to-target
switching and a plaintext addition using the actual planned keys. Its small N
demonstrates functionality and public admission, not cryptographic hardness.

## Representation reuse and resource ownership

Context owns the full sampling state/table and the distinct CRT prefix bases,
half-Q words and Q mod p constants. A client owns one full-N secret and maximum
recovery scratch; lower recovery uses only the selected prefix and integer word
width. Old higher limbs do not enter CRT composition, comparison or reduction.
Fresh public/user private encryption remains at level zero; evaluation-key
zero encryption samples at its own prefix using the same prepared sampler.

The private native gadget adapter reuses `DcrtGlev::mul_crt_polynomial_to` solely
as a componentwise linear sum. Its temporary native column/output views do not
invoke raw b-a*s phase, mask/body interpretation, sign conversion, raw key switch
or raw automorphism. The existing digit/CRT/carry/lift implementation is shared;
only its digit NTT admits a full table with extra higher limbs by visiting the
matching prefix. Existing full-basis raw products perform the same transforms.
No second decomposition kernel, RNS-base clone or NTT-table clone is introduced.

Prepared evaluators own their mutable scratch and borrow immutable keys/context;
independent concurrent requests need independent evaluators. Complete boundary
lengths are checked before output/scratch writes. Arithmetic/RNG/NTT failures can
leave partial output. The complete prepared request is allocation-free; returned
convenience results and key/setup construction allocate. Evaluation-key basis/column
inspection and phase oracles live in private tests;
independent mathematics does not require exposing representation getters.
Temporary secrets/secret products and client recovery scratch follow their
erasure contracts. Public encryptors implement `Zeroize` to clear their
ephemeral scratch while preserving allocation and geometry. Evaluation-key security
and full circuit noise analysis are separate from passing deterministic functionality fixtures.
