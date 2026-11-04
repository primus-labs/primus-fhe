# Native Hybrid evaluation keys

[BFV](../../crates/primus_bfv/README.md) and
[BGV](../../crates/primus_bgv/README.md) select either signed-radix Q keys or
partitioned Hybrid QP keys while keeping native `[c0,c1]` storage and phase
`c0+c1*s`. Their ordinary relin, secret switch and automorphism owners consume
both choices. Hybrid evaluation operates directly in this representation.

## Ordinary workflow

Keep `DecompositionConfig` for the existing radix choice. To use Hybrid, prepare
one immutable parameter owner for each actual key level, then reuse its `Arc`
across roles:

```rust,ignore
let hybrid = context.hybrid_key_parameters(level, decomposition_count, &key_p)?;
let relin_key = client.relinearization_key(level, hybrid.clone(), rng)?;
let rotation_key = client.row_rotation_key(level, &encoder, 1, hybrid, rng)?;
```

Both schemes expose their shared configuration as
`BfvEvaluationKeyConfig` / `BgvEvaluationKeyConfig`, with
`Radix(DecompositionConfig)` and `Hybrid(Arc<NativeHybridParameters>)` variants.
Constructors accept either through `Into`; ordinary prepared requests still
bind their level from the finalized role key. A mixed configuration can be
stored in that enum without introducing a second ciphertext type.

The [coefficient](../../crates/primus_bfv/examples/coefficients.rs) and
[slot](../../crates/primus_bfv/examples/slots.rs) BFV examples, and the matching
BGV examples, accept one optional `--hybrid` argument. Their small parameters
are functional examples. BFV's multiplication backend is a separate choice:
selecting a Hybrid relinearization key does not implicitly select HPSPOVERQ,
and selecting HPSPOVERQ does not choose an evaluation-key backend.

```sh
cargo run -p primus_bfv --example coefficients -- --hybrid
cargo run -p primus_bfv --example slots --features batching -- --hybrid
cargo run -p primus_bgv --example coefficients -- --hybrid
cargo run -p primus_bgv --example slots --features batching -- --hybrid
```

## Bases, partitions and ownership

Let Q be the active ciphertext basis, P the auxiliary **key** basis, and N the
full ciphertext ring length. This P enlarges the evaluation-key RLWE domain to
QP. It is unrelated to a computation-only auxiliary basis used by BFV integer
multiplication. Security analysis must include the actual ordered QP and all
correlated role keys; ciphertext Q alone is insufficient.

The full-chain requested digit count `dnum` fixes
`alpha=ceil(full_q_count/dnum)`. It must produce exactly the requested number of
nonempty contiguous partitions at the full level. Shorter active prefixes keep
that alpha and have their actual number of nonempty partitions beta. The count
is not a bit radix or a multiplicative-depth budget. Generate keys for the
actual level and use their bound parameters; slicing a matrix is not an API for
converting its level or decomposition.

`primus_lattice::hybrid::NativeHybridParameters` owns the immutable Hybrid RNS
bases, constants and P NTT tables. Existing CRT bases share their allocations;
Q NTT tables remain with the scheme context. Role keys share the parameter
owner through `Arc` and each retain only their own public columns. A prepared
operation owns its selected mutable scratch. Prepared numerical `_to` calls
reuse that scratch and caller outputs without allocation; allocating convenience
methods still allocate their returned owners. Independent concurrent calls need
independent mutable operation owners.

Explicit P must be coprime to Q and support the ring's NTT. There is no blanket
`P>Q`, `P>NQ`, or `P>partition_product` requirement. Smaller P can substantially
increase key-product error; construction checks arithmetic compatibility, not
an application error budget. Caller-supplied moduli must actually be suitable
primes; rootability alone does not certify primality.

## Native product and exact correction

For active partition I_j put `Q_j=product(q_i in I_j)`. Its coefficient-domain
ModUp digit is the approximate CRT sum

```text
u_i = [a_i*(Q_j/q_i)^-1] mod q_i
D_j = sum_(i in I_j) u_i*(Q_j/q_i),       0 <= D_j < |I_j|*Q_j.
```

It need not be a canonical or centered lift. The native scalar column weight
w_j is P modulo q_i in I_j and zero in the other Q limbs and every P limb.
The complete identity is

```text
sum_j D_j*w_j = P*a mod QP.
```

Thus the message part has no omitted signed-radix residual. The actual digit
representatives still multiply the key errors and must appear in their bound.
Do not replace them by an assumed small exact lift.

A key column has phase `w_j*h+nu*e_j`, where h is the designated source secret,
s² or sigma(s). BFV uses `nu=1`; BGV uses `nu=p`, its plaintext modulus. Native
accumulation produces T0,T1 in QP. For each component ell:

| Scheme | P correction | Output in Q |
| --- | --- | --- |
| BFV | `r_ell=center_P(T_ell mod P)` | `(T_ell,Q-lift(r_ell))*P^-1 mod Q` |
| BGV | `r_ell=center_P(p^-1*T_ell mod P)` | `(T_ell,Q-p*lift(r_ell))*P^-1 mod Q` |

Here p^-1 is modulo P. BGV requires gcd(p,P)=1, not P congruent to 1 modulo p.
The numerator is exactly divisible by P. Centered conversion certifies its
floating quotient estimate with a conservative interval and falls back to
exact multiword CRT at uncertain half boundaries. Odd P excludes half ties.
These operations are exact component corrections, not an uncorrected
approximate converter relabeled as nearest rounding.

The resulting phase error is, modulo Q,

```text
BFV: (sum_j D_j*e_j-r0-r1*s)/P
BGV: p*(sum_j D_j*e_j-r0-r1*s)/P.
```

The bracketed numerator is divisible by P. With `H=||s||1`, coefficient error
bounds E_j and `B=N*sum_j(|I_j|*Q_j*E_j)`, a conservative added phase bound is
`B/P+(1+H)/2` for BFV and p times that bound for BGV. Use exact integer ceilings
when converting it to an integer budget. These are full-ring convolution
bounds. They exclude input error, other circuit operations and privacy floods;
those must be added at their actual roles and levels. A successful roundtrip
is not a statistical failure or security certificate.

In particular, BGV Hybrid does **not** apply the radix branch's p^-1 input
preprocessing or p-scaled gadget weights. That branch instead encrypts
`p*g_j*h+p*e_j` and has its own truncated-decomposition residual, derived in
[BGV evaluation](bgv-evaluation.md#why-division-by-p-precedes-gadget-decomposition).

## Secret extension and key generation

QP key generation must extend the actual signed coefficient secret. An NTT
entry is an evaluation, so lifting NTT entries as centered coefficients is
incorrect. The shared setup operation
`extend_bounded_secret_to_qp` uses the source client's actual highest-Q base
and tables, verifies canonical representation and the active prefix, and checks
that each coefficient has one unique representative in its configured support.

Small support uses a first-prime inverse transform and verifies every remaining
highest-Q limb. If that first prime cannot identify the support, exact full-Q
CRT checks the positive v and negative v-Q candidates. Out-of-support or truly
ambiguous coefficients are rejected before key randomness. A source owner's
higher tails may differ from the target context; its actual full source Q is
used. Output Q NTT limbs are retained, and only the P limbs are encoded and
transformed. No requirement forces a secret coefficient below P/2. Temporary
secret and CRT buffers erase on error, unwind and normal return.

Relinearization squares that QP secret; automorphism permutes all its QP limbs;
switching extends the actual source and target separately. Errors are sampled
once as signed coefficients across the complete QP basis. BFV encrypts them
unscaled; BGV multiplies them by p exactly once. Native column encryption uses
`c0=weight*h+noise-c1*s` with uniform c1 in QP.

## Collective roles and fresh lookup

Collective setup selects the same radix/Hybrid configuration as ordinary keys.
Public-key setup remains in Q. Evaluation-key common masks, contributions,
canonical import, sums and final columns use the selected actual Q or QP domain.
Transport authenticates the backend, active Q, key P, partitions, actual NTT
convention, role, session and source/target identities before import.

For a common A_j and individual CBD1 shares/ephemeral s_i,u_i, Hybrid two-round
S² generation uses

```text
H0_i = w_j*s_i-A_j*u_i+nu*e0_i
H1_i = A_j*s_i+nu*e1_i
Z_i  = s_i*sum(H0)+(u_i-s_i)*sum(H1)+nu*e2_i.
```

Final `(sum Z,sum H1)` has phase
`w_j*S²+nu*(S*sum e0+U*sum e1+sum e2)`, including every cross term, for
S=sum s_i and U=sum u_i. With G owners, CBD1 secrets/ephemeral and CBD21 errors,
a conservative coefficient bound on the error inside nu is
`2*G²*N*21+G*21`. Independent conditional or statistical bounds need their own
justification. Noncloneable private state is consumed before round two and
cleared on all exits. Count checks do not authenticate a roster; protocol
callers reject missing/duplicate owners and bind the exact frozen round.

BFV fresh mixed lookup retains a separately sampled, consuming
`BfvFreshLookupKey`. Its raw degree-two aggregate is distinct from an ordinary
scaled quadratic. It performs one unscaled native Hybrid relin and adds t0/t1;
it never executes ordinary BFV multiplication, HPSPOVERQ prescaling or t/Q
message scaling. Its key errors/ephemeral must be independent of selector/raw
inputs, including indirect seed or transcript dependencies. Changing key P or
the backend requires rechecking the whole lookup error, privacy flood,
recovery level, security and communication budget.

Finite complete-request and resource measurements are reported separately in the
[performance comparison](../performance/native-hybrid-keys.md). They do not
replace these per-operation mathematical and ownership contracts.
