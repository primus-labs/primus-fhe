# RNS ciphertext phases and explicit representation boundaries

This note fixes the algebra used by the current BFV/BGV/raw boundaries. All equations
are in `R_Q = Z_Q[X]/(X^N+1)`; products are negacyclic polynomial products.
They also hold pointwise in one agreed NTT representation. Equal numerical
moduli alone do not establish matching roots, evaluation order or actual secrets.

## Implemented representations

The rank-one [BFV ciphertext](../../crates/primus_bfv/src/ciphertext.rs) physically
stores `[c0,c1]` and has phase `c0+c1*s`. Native private encryption writes
`c0=Encode(m)+e-c1*s`; native public encryption and recovery use the same plus
convention. Ordinary BFV operations do not convert through raw GLWE.

Raw GLWE stores `[a0,...,a(k-1),b]` and has phase `b-sum(ai*si)`.
For rank one and the **same actual secret**, the explicit bridge is

```text
raw -> BFV: (c0,c1) = (b,-a)
BFV -> raw: (a,b)   = (-c1,c0).
```

The current bridge copies/reorders and canonically negates residues into supplied
storage, without allocating or transforming. It is not a cast. It does not negate
the secret or change a binary secret distribution into `{0,-1}`. Basis, canonical
residues, secret identity and NTT conventions remain caller requirements.

Native BFV encryption/recovery, linear/plaintext evaluation, exact rounded prime
drop, physical components and this bridge are implemented. Native BFV unscaled evaluation keys and full ciphertext multiplication/
relinearization are specified in [BFV evaluation](bfv-evaluation.md). Native BGV now provides quadratic products, p-preserving relin/key switch/
automorphism and exact prefix prime drop; its distinct key/residual equations are
specified in [BGV evaluation](bgv-evaluation.md). Collective Flexilect setup and
opening remain separate future work; existing Relect opening uses raw shares.
The unscaled tensor/key equations below also explain existing raw consumers;
BFV scale-and-round is verified separately against its integer tensor oracle.

## Coefficient evaluation, recovery and exact prime drop

[BfvContext](../../crates/primus_bfv/src/context.rs) owns one highest-level sampler
and NTT table, plus one codec for each requested ordered Q prefix. Level zero uses
all primes. [BfvClient](../../crates/primus_bfv/src/client.rs) stores one full-basis
secret and borrows its prefix for lower-level recovery. Each level retains N and t;
level selection does not reduce the secret's coefficient ring.

For `Delta=floor(Q/t)`, let `r=Q mod t` and `phase=Delta*m+e mod Q`, where m is an
integer polynomial lift. Linear operations add/subtract/negate both components.
Plaintext addition injects `Delta*u` only into c0; plaintext multiplication
multiplies **both** components by the unscaled lift u. No additional Delta enters
that multiplication. If the resulting integer message v is replaced by a chosen
canonical/centered lift `m_out` with `v=m_out+t*h`, its error becomes

```text
linear/plain-mul:  e_out = e_operation - r*h  (mod Q).
plain-mul:        e_operation = e*u.
```

The term `-r*h` follows from `Delta*t=Q-r`; omitting it incorrectly reuses fresh
encryption bounds after message reduction. For a recoverable phase the unique
fast codec returns the exact plaintext. Its sufficient condition is
`abs(t*e-r*m)/Q + k/gamma < 1/2` coefficientwise, where k is the number of Q primes.
This bounded decoder is not an exact `round(t*x/Q)` function on arbitrary phases.
`codec.validate_noise_bound(E, embedding)` checks a conservative uniform version;
it does not measure an evaluated ciphertext's noise.

[BfvModulusSwitch](../../crates/primus_bfv/src/modulus_switch.rs) drops the last
odd prime p, taking `Q'=Q/p`. For a component coefficient x in `[0,Q)`, let
`z=centered(x mod p)`; the exact result is

```text
x' mod qi = (x mod qi - z mod qi) * p^-1 mod qi
           = round(x/p) mod qi.
```

Only the dropped input limb is inverse-transformed. The centered correction is
lifted and forward-transformed in each retained limb; those input limbs stay in
NTT form. This uses one reusable N-element buffer, no online big integers and no
approximate CRT lift. For integer x and odd a,b, nearest rounding composes exactly:
`R_b(R_a(x))=R_(a*b)(x)`, since `(a-1)/2+a*(b-1)/2=(a*b-1)/2`. Reduction modulo
the intermediate Q prefix does not change the final residue. Thus consecutive
exact prime drops agree with division by the product, including wrap to zero.

Let `rho_i=round(c_i/p)-c_i/p` using unreduced integer output lifts, so
`abs(rho_i)<1/2`. With `Delta'=floor(Q'/t)`, the destination phase error satisfies

```text
e' = e/p + (Delta/p-Delta')*m + rho_0 + rho_1*s  (mod Q').
```

Rho times s is negacyclic multiplication. A sufficient magnitude bound includes
`(1+||s||_1)/2` as well as the scaled old error and encoding drift. Equivalently,
`eta=t*e-r*m` obeys `eta'=eta/p+t*(rho_0+rho_1*s)`. Apply this at every level and
check the destination codec margin. A valid context alone establishes neither
this complete evaluated bound nor a security level. For a complete public API
workflow, see [leveled coefficients](../../crates/primus_bfv/examples/leveled_coefficients.rs).

## Tensor products and relinearization

For native inputs `C=(c0,c1)` and `D=(d0,d1)`, the unscaled quadratic tensor is

```text
(t0,t1,t2) = (c0*d0, c0*d1+c1*d0, c1*d1)
phase      = t0+t1*s+t2*s^2 = phase(C)*phase(D).
```

For raw inputs `(a,b),(u,v)`, its plus-polynomial components are instead
`(b*v, -(b*u+a*v), a*u)`. A degree-two ciphertext is not a rank-two GLWE:
its secrets are `1,s,s^2`, rather than `1,s0,s1`.

If digits satisfy `hat(t2)=sum(g_l*d_l)`, a native relinearization key with
`phase(K_l)=g_l*s^2+e_l` gives

```text
Relin(C) = (t0,t1) + sum(d_l*K_l)
phase    = t0+t1*s+hat(t2)*s^2+sum(d_l*e_l).
```

Dropped-digit error and key noise must both enter the recovery bound. Standard
BFV multiplication additionally needs its specified integer lifting and
scale-and-round; the identity above is only unscaled ring algebra. BGV's
plaintext-scaled key/noise constraints and an SSLE mixed unscaled key are separate
contracts, not interchangeable names for a BFV multiplication key.

## GGSW row order and signs

Current raw GGSW rows pair directly with raw input components `[a,b]`. At each
weight `g`, a monomial/message `M` has row phases

| Row | Raw phase | Native plus row required for `[c0,c1]` |
| --- | --- | --- |
| mask / `a` | `-g*M*s` | row 1: `+g*M*s` |
| body / `b` | `+g*M` | row 0: `+g*M` |

Let `F(a,b)=(b,-a)`. A mathematical conversion of stored raw rows is therefore
`Kplus[0,l]=F(Kraw[body,l])` and
`Kplus[1,l]=-F(Kraw[mask,l])`, where the latter negates **both** components.
Only converting each row's internal ciphertext components leaves the mask-row
phase negative and is insufficient. The key's row order, decomposition order and
noise signs must also follow the new contract.

With exact reconstruction, the plus external product phase is
`sum_l d0_l*g_l*M + sum_l d1_l*g_l*M*s = M*(c0+c1*s)`.
This specifies algebra, not equality of actual ciphertexts obtained by different
digit decompositions. Current [raw external product](../../crates/primus_lattice/src/ggsw/dcrt/external_product.rs)
and raw keys retain their existing order and signs; no implicit conversion was added.

## Ordinary and hybrid raw key switching

An ordinary raw switching key from `s_in` to `s_out` has
`phase(K_l)=g_l*s_in+e_l`. For `hat(a)=sum(d_l*g_l)`, the existing raw evaluator
first accumulates `T=sum(d_l*K_l)`, then returns `-T+(0,b)`. Thus

```text
phase(out) = b-hat(a)*s_in-sum(d_l*e_l)
           = phase(in)+(a-hat(a))*s_in-sum(d_l*e_l).
```

See [ordinary switching](../../crates/primus_glwe_rns/src/key_switch/dcrt.rs).
A native plus switch adds the gadget result from `c1` to `(c0,0)`.
BGV implements this using p-scaled columns and a p^-1 preprocessing step as
specified in [its evaluation contract](bgv-evaluation.md). Exporting BFV to raw,
using the existing raw evaluator and importing its output remains an explicit
supported composition; its decomposition input/noise need not match a native
algorithm. Ordinary BFV instead uses the native unscaled gadget path described in
[BFV evaluation](bfv-evaluation.md).

Hybrid raw keys use partition selectors `E_j` (one in their own Q partition,
zero in the other Q limbs) and have phase `P*E_j*s_in+e_j` over QP.
The exact noiseless target is that accumulation has phase `P*a*s_in`.
The implementation performs ModUp/product accumulation, then componentwise
approximate ModDown, then negates, then adds `b`; see
[hybrid switching](../../crates/primus_glwe_rns/src/key_switch/hybrid/switching.rs).
If `T=(T_a,T_b)` and its P lifts are `L_a,L_b`, the ModDown phase is

```text
P^-1 * (T_b-T_a*s_out - L_b + L_a*s_out)  (mod Q).
```

The correction term is real. Neither ideal key phases nor exact scalar division
prove the production ModUp/ModDown error bound. Approximate partition lifts,
key noise and each component's correction must remain in that analysis.

## Negation does not commute with decomposition or ModDown

The [signed decomposition](../../crates/primus_decompose/src/big_integer/basis.rs)
uses digits in `[-B/2,B/2)`, adjusted inputs and carries. Already without dropped
bits, `Q=15,B=4,L=2` gives `Dec(2)=(-2,1)` and `Dec(13)=(-2,0)`.
Both reconstruct correctly modulo 15, but `Dec(-2) != -Dec(2)` as digit vectors.
For `Q=17,B=4,L=2`, one bit is dropped: `Dec(1)=(1,0)` reconstructs 2,
whereas `Dec(16)=(0,0)` reconstructs 0. The rounding tie makes even the
reconstructions fail exact oddness. Do not move a minus sign across `Dec` and
claim unchanged key noise or truncation error.

The current [approximate ModDown](../../crates/primus_rns/src/hybrid/mod_down.rs)
uses `D(z)=(z_Q-FastLift_P(z_P))*P^-1 mod Q`, not centered rounded division.
For a single P prime, `FastLift` is its canonical residue. With `Q=11,P=7`,
`D(1)=0` but `D(-1)=10`, whereas `-D(1)=0`.
With P basis `[3,5]`, its uncorrected CRT sum is
`FastLift(x)=5*(2*x mod 3)+3*(2*x mod 5)`:
for `Q=11`, both `D(1)` and `D(-1)` equal 10. These small integer examples
implement the documented correction formula; they are not NTT or production
hybrid differential tests. Keep the existing negation **after** ModDown unless a
new algorithm explicitly handles its changed correction and bound.

## Additive opening

For `s=sum(s_i)`, raw partial phase is `-a*s_i`, and native plus partial phase
would be `c1*s_i`. Add the body (`b` or `c0`) exactly once, after summing shares;
equivalently, use one full phase and the other partial phases. The bridge
`c1=-a` preserves this equality for the same shares. No sign convention supplies
privacy noise, freshness, one-use policy or retry security. The current low-level
raw partial-phase arithmetic implements no collective opening protocol; a native
BFV partial-phase/protocol API is still future work.
