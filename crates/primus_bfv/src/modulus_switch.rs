use primus_data::{Data, DataMut};
use primus_factor::{FactorSliceOps, ShoupFactor};
use primus_ntt::NttTable;
use primus_reduce::{Reduce, ReduceInv, ReduceSub, ReduceSubSlice};

use crate::{BfvCiphertext, BfvContext};

/// Prepared exact rounded switching from one BFV level to the next.
///
/// The next level drops the last prime `p` of the source's ordered Q basis.
/// Each native component is mapped coefficientwise by
/// `x -> round(x/p) mod (Q/p)`, for its canonical integer lift in `[0,Q)`.
/// All primes are odd, so a tie cannot occur. This is exact nearest rounding,
/// rather than the approximate lift used by hybrid key-switch ModDown.
///
/// One `N`-coefficient buffer and the inverse factors are allocated once at
/// construction. A call only inverse-transforms the dropped limb, then
/// forward-transforms its centered lift in each retained modulus. Retained
/// input limbs stay in NTT form; the supplied output stores those corrections
/// temporarily. Independent concurrent operations need separate switchers.
pub struct BfvModulusSwitch<'a> {
    context: &'a BfvContext,
    source_level: usize,
    inverse_prime: Vec<ShoupFactor<u64>>,
    prime_mod_q: Vec<u64>,
    dropped_coefficients: Vec<u64>,
}

impl<'a> BfvModulusSwitch<'a> {
    /// Prepares a switch that drops one final prime from `source_level`.
    ///
    /// # Panics
    /// Panics before allocating if the source or its next level is unavailable.
    #[must_use]
    pub fn new(context: &'a BfvContext, source_level: usize) -> Self {
        let target_level = source_level
            .checked_add(1)
            .filter(|&level| level < context.level_count())
            .expect("BFV modulus switch needs an available next level");
        let source = context.codec(source_level);
        let target = context.codec(target_level);
        let prime = *source.moduli_values().last().expect("nonempty BFV basis");
        let prime_mod_q: Vec<_> = target
            .base_q()
            .moduli()
            .iter()
            .map(|&modulus| modulus.reduce(prime))
            .collect();
        let inverse_prime = target
            .base_q()
            .moduli()
            .iter()
            .zip(&prime_mod_q)
            .map(|(&modulus, &prime_mod_q)| {
                ShoupFactor::new(modulus.reduce_inv(prime_mod_q), modulus.value())
            })
            .collect();
        Self {
            context,
            source_level,
            inverse_prime,
            prime_mod_q,
            dropped_coefficients: vec![0; context.parameters().poly_length().get()],
        }
    }

    /// Overwrites a complete next-level ciphertext without allocating.
    ///
    /// For each component this computes `(x-lift_centered(x mod p))/p` in
    /// the retained basis. It therefore preserves the native plus convention
    /// `c0+c1*s` and uses the same actual coefficient secret at both levels.
    /// Successive odd-prime drops equal one nearest rounding by their product:
    /// `round(round(x/a)/b)=round(x/(a*b))` for integer `x` and odd `a,b`.
    ///
    /// # Correctness
    /// Input and output use this context's source/next level, ordered bases
    /// and NTT convention, with canonical residues and the same actual secret.
    /// Storage lengths do not prove those identities. Switching adds component
    /// rounding error; fresh recovery bounds do not guarantee evaluated recovery.
    /// If `phase=Delta*m+e` at Q, define `rho_i=round(c_i/p)-c_i/p` using
    /// integer rounded lifts before reducing the output modulo `Q/p`.
    /// The next phase error modulo `Q/p` is
    /// `e'=e/p+(Delta/p-Delta')*m+rho_0+rho_1*s`, with `|rho_i|<1/2`.
    /// Products with `s` are negacyclic. For multiple levels, include this
    /// contribution at every step and use the destination codec's bound.
    ///
    /// # Panics
    /// Both complete ciphertext lengths are checked before writes to output or
    /// scratch. Transform panics can leave partial output and scratch.
    pub fn switch_to<A, B>(&mut self, input: &BfvCiphertext<A>, output: &mut BfvCiphertext<B>)
    where
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        let source_len = self.context.rns_poly_len(self.source_level);
        let target_len = self.context.rns_poly_len(self.source_level + 1);
        let (c0, c1) = input.c0_c1(source_len);
        let (mut output_c0, mut output_c1) = output.c0_c1_mut(target_len);
        self.switch_component(c0.as_ref(), output_c0.as_mut());
        self.switch_component(c1.as_ref(), output_c1.as_mut());
    }

    // Let r be the canonical dropped residue and r_c its centered lift. The
    // integer x-r_c is divisible by p, and differs from p*round(x/p) only by a
    // multiple of Q. NTT linearity lets us keep all retained x limbs transformed.
    fn switch_component(&mut self, input: &[u64], output: &mut [u64]) {
        let context = self.context;
        let n = context.parameters().poly_length().get();
        let source = context.codec(self.source_level);
        let target = context.codec(self.source_level + 1);
        let dropped_index = source.moduli_count() - 1;
        let prime = source.moduli_values()[dropped_index];
        self.dropped_coefficients
            .copy_from_slice(&input[dropped_index * n..]);
        context.table().ntt_tables()[dropped_index]
            .inverse_transform_slice(&mut self.dropped_coefficients);

        for (((((input_limb, output_limb), &modulus), table), &prime_mod_q), &inverse) in input
            .chunks_exact(n)
            .zip(output.chunks_exact_mut(n))
            .zip(target.base_q().moduli())
            .zip(context.table().ntt_tables())
            .zip(&self.prime_mod_q)
            .zip(&self.inverse_prime)
        {
            for (&residue, correction) in
                self.dropped_coefficients.iter().zip(output_limb.iter_mut())
            {
                let residue_mod_q = modulus.reduce(residue);
                *correction = if residue > prime / 2 {
                    modulus.reduce_sub(residue_mod_q, prime_mod_q)
                } else {
                    residue_mod_q
                };
            }
            table.transform_slice(output_limb);
            modulus.reduce_sub_slice_rev_assign(input_limb, output_limb);
            inverse.factor_mul_slice_assign(output_limb, modulus.value());
        }
    }
}
