use crate::correction::{self, Alignment};
use primus_data::{Data, DataMut};
use primus_factor::{FactorMul, ShoupFactor};
use primus_ntt::NttTable;
use primus_poly::{DcrtPolynomial, Polynomial};
use primus_reduce::{ReduceAdd, ReduceSub};

use crate::client::validate_plaintext;
use crate::{BgvCiphertext, BgvContext, PlaintextEmbedding};

/// Prepared BGV linear and plaintext operations at one Q level.
///
/// The evaluator borrows immutable parameters/tables and uses one reusable
/// plaintext polynomial, owned by default or borrowed from a worker. It retains
/// no key or RNG and allocates nothing after
/// construction. Both addition and multiplication lift plaintext without a
/// BFV Delta or another factor of p.
///
/// # Correctness
/// Ciphertexts must use this context's ordered basis, canonical NTT residues,
/// actual secret and transform convention. Matching lengths do not establish
/// these conditions. Context-created inputs/outputs are checked against this
/// exact context and level; explicit raw inputs attest those numerical contracts.
/// Neither path proves the intended secret. The centered phase must fit
/// in (-Q/2,Q/2): reducing a phase by Q can change its residue modulo p even
/// for arbitrary coprime p and q_i. Parameter fresh-private bounds do not establish
/// a bound for public encryption or a complete evaluated circuit.
pub struct BgvEvaluator<'a, S: DataMut<Elem = u64> = Vec<u64>> {
    context: &'a BgvContext,
    level: usize,
    plaintext: DcrtPolynomial<S>,
}

impl<'a> BgvEvaluator<'a> {
    /// Binds one prepared level and allocates a reusable CRT/NTT plaintext buffer.
    ///
    /// # Panics
    /// Rejects an unprepared level before allocating.
    #[must_use]
    pub fn new(context: &'a BgvContext, level: usize) -> Self {
        Self {
            context,
            level,
            plaintext: DcrtPolynomial::zero(context.rns_poly_len(level)),
        }
    }
}

impl<'a, S: DataMut<Elem = u64>> BgvEvaluator<'a, S> {
    /// Borrows or owns one complete plaintext scratch polynomial at this level.
    ///
    /// Scratch may contain arbitrary words. Construction and linear operations
    /// leave it untouched; each plaintext operation overwrites all active words
    /// before reading them. A worker can reuse one maximum-sized allocation by
    /// lending an exact prefix to one operation at a time. This constructor
    /// allocates nothing and does not change the context's numerical binding.
    ///
    /// # Panics
    /// Rejects an unprepared level or a scratch length other than N times the
    /// active modulus count, before touching the supplied storage.
    #[must_use]
    pub fn with_plaintext_scratch(context: &'a BgvContext, level: usize, plaintext: S) -> Self {
        assert_eq!(
            plaintext.len(),
            context.rns_poly_len(level),
            "BGV evaluator plaintext scratch length mismatch"
        );
        Self {
            context,
            level,
            plaintext: DcrtPolynomial(plaintext),
        }
    }

    /// Writes the ciphertext sum, aligning unequal message factors with centered scalars.
    ///
    /// # Panics
    /// Recorded context/level and every complete length are checked before writes.
    pub fn add_to<A, B, C>(
        &self,
        lhs: &BgvCiphertext<A>,
        rhs: &BgvCiphertext<B>,
        output: &mut BgvCiphertext<C>,
    ) where
        A: Data<Elem = u64>,
        B: Data<Elem = u64>,
        C: DataMut<Elem = u64>,
    {
        self.linear_to(lhs, rhs, output, false);
    }

    /// Adds the logical messages in place, aligning unequal correction factors.
    ///
    /// # Panics
    /// Rejects recorded context/level mismatches or incorrect complete lengths before writes.
    pub fn add_assign<A, B>(&self, input: &mut BgvCiphertext<A>, rhs: &BgvCiphertext<B>)
    where
        A: DataMut<Elem = u64>,
        B: Data<Elem = u64>,
    {
        self.linear_assign(input, rhs, false);
    }

    /// Writes the ciphertext difference after the same factor alignment as addition.
    ///
    /// # Panics
    /// Recorded context/level and every complete length are checked before writes.
    pub fn sub_to<A, B, C>(
        &self,
        lhs: &BgvCiphertext<A>,
        rhs: &BgvCiphertext<B>,
        output: &mut BgvCiphertext<C>,
    ) where
        A: Data<Elem = u64>,
        B: Data<Elem = u64>,
        C: DataMut<Elem = u64>,
    {
        self.linear_to(lhs, rhs, output, true);
    }

    /// Subtracts the logical messages in place, aligning unequal correction factors.
    ///
    /// # Panics
    /// Rejects recorded context/level mismatches or incorrect complete lengths before writes.
    pub fn sub_assign<A, B>(&self, input: &mut BgvCiphertext<A>, rhs: &BgvCiphertext<B>)
    where
        A: DataMut<Elem = u64>,
        B: Data<Elem = u64>,
    {
        self.linear_assign(input, rhs, true);
    }

    /// Writes the component-wise ciphertext negation.
    ///
    /// # Panics
    /// Rejects recorded context/level mismatches or incorrect complete lengths before writes.
    pub fn neg_to<A, B>(&self, input: &BgvCiphertext<A>, output: &mut BgvCiphertext<B>)
    where
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        input.check_binding(self.context, self.level);
        output.check_binding(self.context, self.level);
        let length = self.plaintext.as_ref().len();
        let (input0, input1) = input.c0_c1(length);
        let (mut output0, mut output1) = output.c0_c1_mut(length);
        let n = self.context.parameters().poly_length().get();
        let moduli = self.context.base_q(self.level).moduli();
        input0.neg_to(&mut output0, n, moduli);
        input1.neg_to(&mut output1, n, moduli);
        output.set_correction_factor(input.correction_factor());
    }

    /// Negates both ciphertext components in place.
    ///
    /// # Panics
    /// Rejects recorded context/level mismatches or an incorrect complete length before writes.
    pub fn neg_assign<A>(&self, input: &mut BgvCiphertext<A>)
    where
        A: DataMut<Elem = u64>,
    {
        input.check_binding(self.context, self.level);
        let (mut input0, mut input1) = input.c0_c1_mut(self.plaintext.as_ref().len());
        let n = self.context.parameters().poly_length().get();
        let moduli = self.context.base_q(self.level).moduli();
        input0.neg_assign(n, moduli);
        input1.neg_assign(n, moduli);
    }

    /// Adds a factor-adjusted plaintext lift to c0, retaining c1 unchanged.
    ///
    /// `plain` contains N canonical polynomial coefficients in `[0,p)`, not slots.
    /// Addition first multiplies coefficients by the input correction factor modulo p,
    /// then applies the unsigned/centered lift selected by `embedding`.
    ///
    /// # Panics
    /// Recorded context/level, complete lengths and all plaintext values are checked
    /// before output or scratch writes. Transform panics can modify scratch.
    pub fn add_plain_to<A, B, C>(
        &mut self,
        input: &BgvCiphertext<A>,
        plain: &Polynomial<B>,
        output: &mut BgvCiphertext<C>,
        embedding: PlaintextEmbedding,
    ) where
        A: Data<Elem = u64>,
        B: Data<Elem = u64>,
        C: DataMut<Elem = u64>,
    {
        input.check_binding(self.context, self.level);
        output.check_binding(self.context, self.level);
        let length = self.plaintext.as_ref().len();
        let (input0, input1) = input.c0_c1(length);
        let (mut output0, mut output1) = output.c0_c1_mut(length);
        self.prepare_plaintext(plain, embedding, input.correction_factor());
        input0.add_to(
            &self.plaintext,
            &mut output0,
            self.context.parameters().poly_length().get(),
            self.context.base_q(self.level).moduli(),
        );
        output1.as_mut().copy_from_slice(input1.as_ref());
        output.set_correction_factor(input.correction_factor());
    }

    /// Adds the factor-adjusted plaintext lift to c0, retaining c1 and the factor.
    /// The embedding and panic contract is [`Self::add_plain_to`]'s.
    pub fn add_plain_assign<A, B>(
        &mut self,
        input: &mut BgvCiphertext<A>,
        plain: &Polynomial<B>,
        embedding: PlaintextEmbedding,
    ) where
        A: DataMut<Elem = u64>,
        B: Data<Elem = u64>,
    {
        input.check_binding(self.context, self.level);
        let factor = input.correction_factor();
        let (mut input0, _) = input.c0_c1_mut(self.plaintext.as_ref().len());
        self.prepare_plaintext(plain, embedding, factor);
        input0.add_assign(
            &self.plaintext,
            self.context.parameters().poly_length().get(),
            self.context.base_q(self.level).moduli(),
        );
    }

    /// Multiplies both native components by an unscaled plaintext lift.
    ///
    /// This is negacyclic polynomial multiplication in `Z_p[X]/(X^N+1)`;
    /// No Delta, correction factor or extra p scale is applied to the plaintext.
    /// Canonical plaintext and panic requirements are [`Self::add_plain_to`]'s;
    /// the lift uses `embedding` directly. Complete evaluated noise must be checked separately.
    pub fn mul_plain_to<A, B, C>(
        &mut self,
        input: &BgvCiphertext<A>,
        plain: &Polynomial<B>,
        output: &mut BgvCiphertext<C>,
        embedding: PlaintextEmbedding,
    ) where
        A: Data<Elem = u64>,
        B: Data<Elem = u64>,
        C: DataMut<Elem = u64>,
    {
        input.check_binding(self.context, self.level);
        output.check_binding(self.context, self.level);
        let length = self.plaintext.as_ref().len();
        let (input0, input1) = input.c0_c1(length);
        let (mut output0, mut output1) = output.c0_c1_mut(length);
        self.prepare_plaintext(plain, embedding, 1);
        let n = self.context.parameters().poly_length().get();
        let moduli = self.context.base_q(self.level).moduli();
        input0.mul_to(&self.plaintext, &mut output0, n, moduli);
        input1.mul_to(&self.plaintext, &mut output1, n, moduli);
        output.set_correction_factor(input.correction_factor());
    }

    /// Multiplies both components by the unscaled lift in place.
    /// The embedding and panic contract is [`Self::mul_plain_to`]'s.
    pub fn mul_plain_assign<A, B>(
        &mut self,
        input: &mut BgvCiphertext<A>,
        plain: &Polynomial<B>,
        embedding: PlaintextEmbedding,
    ) where
        A: DataMut<Elem = u64>,
        B: Data<Elem = u64>,
    {
        input.check_binding(self.context, self.level);
        let (mut input0, mut input1) = input.c0_c1_mut(self.plaintext.as_ref().len());
        self.prepare_plaintext(plain, embedding, 1);
        let n = self.context.parameters().poly_length().get();
        let moduli = self.context.base_q(self.level).moduli();
        input0.mul_assign(&self.plaintext, n, moduli);
        input1.mul_assign(&self.plaintext, n, moduli);
    }

    fn linear_to<A, B, C>(
        &self,
        lhs: &BgvCiphertext<A>,
        rhs: &BgvCiphertext<B>,
        output: &mut BgvCiphertext<C>,
        subtract: bool,
    ) where
        A: Data<Elem = u64>,
        B: Data<Elem = u64>,
        C: DataMut<Elem = u64>,
    {
        lhs.check_binding(self.context, self.level);
        rhs.check_binding(self.context, self.level);
        output.check_binding(self.context, self.level);
        let len = self.plaintext.as_ref().len();
        let (lhs0, lhs1) = lhs.c0_c1(len);
        let (rhs0, rhs1) = rhs.c0_c1(len);
        let (mut out0, mut out1) = output.c0_c1_mut(len);
        let p = self.context.parameters().plain_modulus().value();
        let aligned = correction::align(lhs.correction_factor(), rhs.correction_factor(), p);
        let n = self.context.parameters().poly_length().get();
        let moduli = self.context.base_q(self.level).moduli();
        if aligned.lhs_scale == 1 && aligned.rhs_scale == 1 {
            if subtract {
                lhs0.sub_to(&rhs0, &mut out0, n, moduli);
                lhs1.sub_to(&rhs1, &mut out1, n, moduli);
            } else {
                lhs0.add_to(&rhs0, &mut out0, n, moduli);
                lhs1.add_to(&rhs1, &mut out1, n, moduli);
            }
        } else {
            self.scaled_linear_to(
                lhs.as_ref(),
                rhs.as_ref(),
                output.as_mut(),
                aligned,
                subtract,
            );
        }
        output.set_correction_factor(aligned.factor);
    }

    fn linear_assign<A, B>(
        &self,
        input: &mut BgvCiphertext<A>,
        rhs: &BgvCiphertext<B>,
        subtract: bool,
    ) where
        A: DataMut<Elem = u64>,
        B: Data<Elem = u64>,
    {
        input.check_binding(self.context, self.level);
        rhs.check_binding(self.context, self.level);
        let p = self.context.parameters().plain_modulus().value();
        let aligned = correction::align(input.correction_factor(), rhs.correction_factor(), p);
        let len = self.plaintext.as_ref().len();
        let (mut input0, mut input1) = input.c0_c1_mut(len);
        let (rhs0, rhs1) = rhs.c0_c1(len);
        let n = self.context.parameters().poly_length().get();
        let moduli = self.context.base_q(self.level).moduli();
        if aligned.lhs_scale == 1 && aligned.rhs_scale == 1 {
            if subtract {
                input0.sub_assign(&rhs0, n, moduli);
                input1.sub_assign(&rhs1, n, moduli);
            } else {
                input0.add_assign(&rhs0, n, moduli);
                input1.add_assign(&rhs1, n, moduli);
            }
        } else {
            for ((left, right), &q) in input
                .as_mut()
                .chunks_exact_mut(n)
                .zip(rhs.as_ref().chunks_exact(n))
                .zip(moduli.iter().cycle())
            {
                let a = scalar_factor(aligned.lhs_scale, p, q.value());
                let b = scalar_factor(aligned.rhs_scale, p, q.value());
                for (out, &right) in left.iter_mut().zip(right) {
                    let left = a.factor_mul_modulo(*out, q.value());
                    let right = b.factor_mul_modulo(right, q.value());
                    *out = if subtract {
                        q.reduce_sub(left, right)
                    } else {
                        q.reduce_add(left, right)
                    };
                }
            }
        }
        input.set_correction_factor(aligned.factor);
    }

    // The shape and factors were established by the whole-ciphertext entry.
    // Signed centered scalars are embedded into each q, so the runtime scaling
    // is exactly what the planner's centered absolute weights bound.
    fn scaled_linear_to(
        &self,
        lhs: &[u64],
        rhs: &[u64],
        output: &mut [u64],
        aligned: Alignment,
        subtract: bool,
    ) {
        let n = self.context.parameters().poly_length().get();
        let p = self.context.parameters().plain_modulus().value();
        for (((left, right), out), &q) in lhs
            .chunks_exact(n)
            .zip(rhs.chunks_exact(n))
            .zip(output.chunks_exact_mut(n))
            .zip(self.context.base_q(self.level).moduli().iter().cycle())
        {
            let a = scalar_factor(aligned.lhs_scale, p, q.value());
            let b = scalar_factor(aligned.rhs_scale, p, q.value());
            for ((&left, &right), out) in left.iter().zip(right).zip(out) {
                let left = a.factor_mul_modulo(left, q.value());
                let right = b.factor_mul_modulo(right, q.value());
                *out = if subtract {
                    q.reduce_sub(left, right)
                } else {
                    q.reduce_add(left, right)
                };
            }
        }
    }

    fn prepare_plaintext<A>(
        &mut self,
        plain: &Polynomial<A>,
        embedding: PlaintextEmbedding,
        factor: u64,
    ) where
        A: Data<Elem = u64>,
    {
        let parameters = self.context.parameters();
        let n = parameters.poly_length().get();
        let p = parameters.plain_modulus().value();
        validate_plaintext(self.context, plain.as_ref());
        let half = p.div_ceil(2);
        if factor == 1 {
            for (limb, &q) in self
                .plaintext
                .iter_each_modulus_mut(n)
                .zip(self.context.base_q(self.level).moduli_values())
            {
                match embedding {
                    PlaintextEmbedding::Unsigned => limb.copy_from_slice(plain.as_ref()),
                    PlaintextEmbedding::Centered => {
                        for (&value, residue) in plain.as_ref().iter().zip(limb) {
                            *residue = if value < half { value } else { q - (p - value) };
                        }
                    }
                }
            }
        } else {
            // Scale once in Z_p, then lift those canonical coefficients. Scaling
            // an already lifted polynomial would incur a different phase bound.
            let scale = ShoupFactor::new(factor, p);
            let (first, remaining) = self.plaintext.as_mut().split_at_mut(n);
            for (out, &value) in first.iter_mut().zip(plain.as_ref()) {
                *out = scale.factor_mul_modulo(value, p);
            }
            for limb in remaining.chunks_exact_mut(n) {
                limb.copy_from_slice(first);
            }
            if embedding == PlaintextEmbedding::Centered {
                for (limb, &q) in self
                    .plaintext
                    .iter_each_modulus_mut(n)
                    .zip(self.context.base_q(self.level).moduli_values())
                {
                    for value in limb {
                        if *value >= half {
                            *value = q - (p - *value);
                        }
                    }
                }
            }
        }
        for (table, limb) in self
            .context
            .table()
            .iter()
            .zip(self.plaintext.as_mut().chunks_exact_mut(n))
        {
            table.transform_slice(limb);
        }
    }
}

// p<q; a negative centered scalar is represented by q-(p-scale), never by
// the larger nonnegative residue scale. This avoids an unbudgeted p multiple.
fn scalar_factor(scale: u64, p: u64, q: u64) -> ShoupFactor<u64> {
    ShoupFactor::new(
        if scale > p / 2 {
            q - (p - scale)
        } else {
            scale
        },
        q,
    )
}
