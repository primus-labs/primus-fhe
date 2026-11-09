# Native BFV multiplication and evaluation

All scheme components are rank-one, fixed-`u64` RNS polynomials. A degree-one
ciphertext stores `[c0,c1]` with phase `c0+c1*s`; `Q` can have arbitrarily many
machine words. This contract supplements the [BFV README](../../crates/primus_bfv/README.md)
and [phase conventions](rns-phase-conventions.md).

## Integer tensor and scale

Take the exact centered integer coefficient lifts of each input component,
in `[-(Q-1)/2,(Q-1)/2]`, in `Z[X]/(X^N+1)`. Compute

```text
T0 = c0*d0
T1 = c0*d1 + c1*d0
T2 = c1*d1
ui = round(t*Ti/Q) mod Q.
```

Cross terms are added before rounding. Squaring uses `T1=2*c0*c1`. Each `Ti`
is an integer negacyclic product before reduction modulo Q, matching the target
in [Halevi–Polyakov–Shoup §4.1](https://www.shoup.net/papers/rns-bfv.pdf). A tensor computed
only in Q has discarded the multiples of Q needed by the scaling operation.
The scale is `t/Q`, even though encryption uses `Delta=floor(Q/t)`; it is not
division by Delta. Q is odd, so these rational values have no half-integer ties.

The multiplier retains the unscaled product in private QP scratch; independent
raw/scaled representation oracles live in private tests.
`BfvQuadraticCiphertext` stores the already-scaled `[u0,u1,u2]` in Q. It can only
be consumed by relinearization, storage/views or explicit advanced inspection.
Ordinary degree-one evaluators, decryption, switching and automorphisms require
relinearization first. Neither object uses GLWE rank two to represent s².

## Exact RNS NTT backend

`BfvMultiplier::try_new(context,level,&auxiliary_moduli)` prepares a computation-only
P with NTT-compatible odd primes, coprime to Q, and verifies **P>N*Q**. Let
`h=(Q-1)/2`. The outer tensor components satisfy `|Ti|<=N*h²` and the middle
component satisfies `|T1|<=2*N*h²`. Thus `Q*P>N*Q²>4*N*h²` uniquely retains the
signed integer tensor. Auxiliary primes do not enlarge encryption, secrets,
evaluation keys, the modulus chain or the coefficient codec. Actual primality
remains a caller precondition; finding compatible NTT roots does not certify it.

The multiplier borrows the existing Q basis/table. It inverse-transforms input
components, exactly composes their canonical Q representatives, then subtracts Q
for values above h before lifting to P. No floating-point base conversion is
used. Q products reuse the input NTT residues; P products use auxiliary NTTs.

For every coefficient z of the tensor, recover

```text
r = CRT_Q(z mod Q),              0 <= r < Q
k = (z-r)/Q
k mod pj = (z mod pj - r mod pj)*Q^-1 mod pj
round(t*z/Q) mod qi = t*(k mod qi) + floor((t*r+floor(Q/2))/Q) mod qi.
```

Since `|k|<N*Q/2<P/2`, exact centered CRT in P recovers k. The remaining
nonnegative quotient is at most t and fits u64; fixed-width integer operations
compute it exactly. This route needs P>NQ because it recovers k before multiplying
by t. A route that reconstructs the final scaled integer in P would need a
different bound involving t. These bounds are not interchangeable.

A private integer schoolbook implementation retains a separate signed integer
tensor and exact scaling algorithm as an independent test oracle. It needs no
auxiliary basis and is not a runtime fallback or a public benchmark interface.
Mathematical independence comes from the separate algorithm, rather than public
visibility of keys or raw buffers. The production path uses exact RNS NTT.

For ordinary degree-one requests, prepare
`BfvMultiplication::try_new(context,&relinearization_key)`. It derives the actual
level from the key, selects compatible computation-only primes and owns the scaled
quadratic/relinearization scratch. `multiply_to` and `square_to` return degree-one
outputs; `square_assign` overwrites one ciphertext using the same internal scratch.
Advanced callers can explicitly choose the auxiliary basis with
`try_with_auxiliary_moduli(context,key,&primes)`, or retain the separate
`BfvMultiplier` → scaled quadratic → `BfvRelinearizer` flow.
The [multiplication benchmark](../../crates/primus_bfv/benches/multiplication.rs)
uses the combined public request and explicit historical P to keep its full fresh
request comparable. It does not expose internal oracles solely for measurement.

## Phase error and fixed Delta

Integer products, errors and carries below are negacyclic polynomials. Write
the centered component phases as `PhiA=Delta*m+e+Q*v` and
`PhiB=Delta*n+f+Q*w`, and put `rQ=Q-t*Delta`. If
`rho_i=round(t*Ti/Q)-t*Ti/Q`, then
`R=rho0+rho1*s+rho2*s²`. Modulo Q, the scaled phase is `Delta*m*n+E`, where

```text
E = -(Delta*rQ/Q)*m*n + (t*Delta/Q)*(m*f+n*e) + (t/Q)*e*f
    - rQ*(m*w+n*v) + t*(v*f+w*e) + R.
```

For a chosen canonical product representative `mu=m*n-t*z`, its error becomes
`E-rQ*z`. This records fixed-Delta drift, integer phase carries and all three
component rounding errors; it does not assume `t*Delta=Q`. A conservative bound
for R is `(1+||s||1+||s²||1)/2`. Actual recovered messages must satisfy the
destination codec's complete error condition. Functional tests and the small
demonstration/benchmark parameters do not certify security or arbitrary depth.

## Native unscaled gadget keys

At each actual modulus level, role-specific keys encrypt `g_j*h+e_j` under the
destination secret. Here h is s² for relinearization, the source secret for
key switching, or the transformed secret for automorphisms. BFV uses ordinary
unscaled key noise. There is no BGV p^-1 preprocessing or p-scaled key column.

If decomposed a satisfies `sum(d_j*g_j)=a+epsilon`, the product contributes
`a*h+epsilon*h+sum(d_j*e_j)`. Even the maximum configured digit count can drop
low bits when the Q bit width is not divisible by the radix log; truncated
decomposition residual is real BFV error. Relinearization adds this product to
`[u0,u1]`. Key switching adds it to `[c0,0]`. An automorphism first permutes the
NTT values to obtain phase under sigma(s), then switches back to s.

Keys bind role, N, t, level, ordered Q and actual gadget basis. Prepared operations
check complete shapes before writes. Equal numerical parameters do not authenticate
the actual secret, canonical residues or NTT convention; those remain caller
contracts. Source and destination clients may share immutable context resources.
The shared GLev kernel only decomposes and accumulates components; it does not
interpret a native BFV ciphertext as raw GLWE or apply a phase sign conversion.

`BfvRelinearizer::try_new(context,key)`, `BfvKeySwitcher::try_new(context,key)`
and `BfvAutomorphism::try_new(context,key)` derive the level from the bound key,
as does `BfvMultiplication`. The context must have prepared that level and match
the key's N, t and ordered Q. Key generation, ordinary linear evaluation,
decryption and prime drop still select their levels explicitly; ciphertext
storage does not carry the metadata needed to infer them.

## Levels, slots and resources

Relinearize before exact BFV prime drop. The existing componentwise rounded drop
changes Delta and adds its documented scale-mismatch/rounding error. Keys and
multipliers are prepared for each level where they are used. Full-ring secrets
remain full N when shared batching embeds a smaller plaintext subring. Row
rotation/swap uses the encoder's actual automorphism exponents; spare slots and
off-stride coefficients remain zero in the complete examples.

With `batching`, `context.batching_encoder()` prepares an existing shared encoder
for N slots using the context's t. Construct a smaller encoder explicitly for an
embedded plaintext subring. `client.row_rotation_key(level,&encoder,steps,config,rng)`
accepts signed row-left steps, normalized modulo the encoder's row length;
`row_swap_key(level,&encoder,config,rng)` exchanges rows. Both validate the
encoder's plaintext modulus and capacity before sampling, then generate ordinary
automorphism keys. They neither retain another encoder nor resize the secret.
The direct exponent-based `automorphism_key` remains the general ring operation.

Context owns the unique Q tables/codecs/samplers. A multiplier owns P and its
tables, constants and mutable arithmetic scratch. The ordinary multiplication
owner additionally reuses a scaled quadratic and relinearization scratch. Private
reference scratch is constructed only by mathematical tests. Prepared key products
own decomposition scratch and borrow existing Q tables/bases/immutable keys. No per-operation resource
cloning, sampler construction or domain wrapper is required.
