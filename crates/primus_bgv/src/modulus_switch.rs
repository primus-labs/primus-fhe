use primus_data::{Data, DataMut};
use primus_factor::{FactorSliceOps, ShoupFactor};
use primus_ntt::NttTable;
use primus_reduce::{Reduce, ReduceInv, ReduceMul, ReduceSub, ReduceSubSlice};

use crate::{BgvCiphertext, BgvContext};

/// Prepared exact switching to the adjacent BGV level with correction tracking.
///
/// Let `q` be the source basis's final prime and `p` the plaintext modulus.
/// For each native component coefficient this computes
/// `y = (x - p * center_q(x * p^-1 mod q)) / q mod (Q/q)`.
/// The numerator is exactly divisible by q. The plaintext correction becomes
/// `f*q^-1 mod p`; no factor change occurs in the special q=1 modulo p family.
/// Ordinary nearest division by q would not preserve this congruence.
///
/// Only the dropped limb is inverse transformed. Retained limbs remain in NTT
/// form, and the output temporarily stores the transformed p-scaled correction.
/// Construction allocates one N-coefficient buffer and inverse factors; calls
/// allocate nothing. Total Q need not fit u128. Independent concurrent requests
/// require separate switchers.
pub struct BgvModulusSwitch<'a> {
    context: &'a BgvContext,
    source_level: usize,
    inverse_plaintext: ShoupFactor<u64>,
    inverse_prime_mod_plaintext: u64,
    inverse_prime: Vec<ShoupFactor<u64>>,
    plain_factors: Vec<ShoupFactor<u64>>,
    prime_mod_q: Vec<u64>,
    dropped_coefficients: Vec<u64>,
}

impl<'a> BgvModulusSwitch<'a> {
    /// Prepares a switch that drops the final prime of `source_level`.
    ///
    /// # Panics
    /// Panics before allocation unless both source and adjacent target levels
    /// are prepared in this context.
    #[must_use]
    pub fn new(context: &'a BgvContext, source_level: usize) -> Self {
        let target_level = source_level
            .checked_add(1)
            .filter(|&level| level < context.level_count())
            .expect("BGV modulus switch needs an available next level");
        let source = context.base_q(source_level);
        let target = context.base_q(target_level);
        let prime = *source.moduli().last().expect("nonempty BGV basis");
        let p = context.parameters().plain_modulus().value();
        let inverse_plaintext = ShoupFactor::new(prime.reduce_inv(p), prime.value());
        let plaintext = context.parameters().plain_modulus();
        let inverse_prime_mod_plaintext = plaintext.reduce_inv(plaintext.reduce(prime.value()));
        let prime_mod_q: Vec<_> = target
            .moduli()
            .iter()
            .map(|&modulus| modulus.reduce(prime.value()))
            .collect();
        let inverse_prime = target
            .moduli()
            .iter()
            .zip(&prime_mod_q)
            .map(|(&modulus, &prime_mod_q)| {
                ShoupFactor::new(modulus.reduce_inv(prime_mod_q), modulus.value())
            })
            .collect();
        let plain_factors = target
            .moduli()
            .iter()
            .map(|modulus| ShoupFactor::new(p, modulus.value()))
            .collect();
        Self {
            context,
            source_level,
            inverse_plaintext,
            inverse_prime_mod_plaintext,
            inverse_prime,
            plain_factors,
            prime_mod_q,
            dropped_coefficients: vec![0; context.parameters().poly_length().get()],
        }
    }

    /// Overwrites a complete adjacent-level ciphertext without allocating.
    ///
    /// Both native components are switched with the same actual secret. If an
    /// intended integer phase is `z = lift(f*m) + p*e` and `r_i` are the centered
    /// inverse-p residues of its components, the new phase modulo `Q/q` is
    /// `z' = (z - p*(r_0 + r_1*s))/q`. Products with s are negacyclic. Its message
    /// factor is `f*q^-1 mod p`; the decoder removes that factor only after
    /// centered phase recovery. This metadata does not replace the full phase
    /// and component-rounding error bound.
    ///
    /// # Correctness
    /// Input and output use this context's source/adjacent ordered bases and
    /// NTT convention, with canonical residues and the same actual secret.
    /// Local context/level provenance is checked when present; explicit raw
    /// storage attests it. Neither provenance nor length proves the secret.
    /// The intended new phase
    /// must lie in the target centered interval for exact BGV recovery; this
    /// operation does not establish an evaluated noise bound. It accepts
    /// ordinary two-component ciphertexts, not unrelinearized quadratic ones.
    ///
    /// # Panics
    /// Recorded context/level and both complete lengths are checked before output or
    /// scratch writes. A transform panic may leave partially written buffers.
    pub fn switch_to<A, B>(&mut self, input: &BgvCiphertext<A>, output: &mut BgvCiphertext<B>)
    where
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        input.check_binding(self.context, self.source_level);
        output.check_binding(self.context, self.source_level + 1);
        let source_len = self.context.rns_poly_len(self.source_level);
        let target_len = self.context.rns_poly_len(self.source_level + 1);
        let (c0, c1) = input.c0_c1(source_len);
        let (mut output_c0, mut output_c1) = output.c0_c1_mut(target_len);
        self.switch_component(c0.as_ref(), output_c0.as_mut());
        self.switch_component(c1.as_ref(), output_c1.as_mut());
        let factor = input.correction_factor();
        let factor = if self.inverse_prime_mod_plaintext == 1 {
            factor
        } else {
            self.context
                .parameters()
                .plain_modulus()
                .reduce_mul(factor, self.inverse_prime_mod_plaintext)
        };
        output.set_correction_factor(factor);
    }

    // The discarded residue alone determines the exact p-constrained remainder.
    // Reduce and multiply in each retained modulus: the integer p*r can be much
    // wider than u64 even though every RNS input and result fits one limb.
    fn switch_component(&mut self, input: &[u64], output: &mut [u64]) {
        let n = self.context.parameters().poly_length().get();
        let source = self.context.base_q(self.source_level);
        let target = self.context.base_q(self.source_level + 1);
        let dropped_index = source.moduli_count() - 1;
        let prime = source.moduli_values()[dropped_index];
        self.dropped_coefficients
            .copy_from_slice(&input[dropped_index * n..]);
        self.context.table().ntt_tables()[dropped_index]
            .inverse_transform_slice(&mut self.dropped_coefficients);
        self.inverse_plaintext
            .factor_mul_slice_assign(&mut self.dropped_coefficients, prime);

        for (index, ((input_limb, output_limb), (&modulus, table))) in input
            .chunks_exact(n)
            .zip(output.chunks_exact_mut(n))
            .zip(
                target
                    .moduli()
                    .iter()
                    .zip(self.context.table().ntt_tables()),
            )
            .enumerate()
        {
            for (&residue, correction) in
                self.dropped_coefficients.iter().zip(output_limb.iter_mut())
            {
                let residue_mod_q = modulus.reduce(residue);
                *correction = if residue > prime / 2 {
                    modulus.reduce_sub(residue_mod_q, self.prime_mod_q[index])
                } else {
                    residue_mod_q
                };
            }
            self.plain_factors[index].factor_mul_slice_assign(output_limb, modulus.value());
            table.transform_slice(output_limb);
            modulus.reduce_sub_slice_rev_assign(input_limb, output_limb);
            self.inverse_prime[index].factor_mul_slice_assign(output_limb, modulus.value());
        }
    }
}
