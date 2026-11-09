use primus_data::{Data, DataMut};
use primus_ntt::NttTable;
use primus_poly::{CrtPolynomial, DcrtPolynomial, Polynomial};

use crate::{BfvCiphertext, BfvContext, PlaintextEmbedding};

/// Prepared linear and plaintext operations at one BFV modulus-chain level.
///
/// Level zero is the context's complete Q basis; later levels use its ordered
/// prefixes. The evaluator borrows the unique codec/tables and owns one reusable
/// plaintext polynomial. No secret, public key or RNG state is retained.
/// All operations allocate nothing after construction. Bound operands must use
/// this exact local context and level; mismatches are rejected before writes.
/// Explicit raw operands retain caller-attested representation contracts.
///
/// # Correctness
/// Ciphertexts must use this level's ordered basis, canonical NTT residues and
/// the same actual secret and NTT convention. Matching lengths do not establish
/// these conditions. Evaluated noise, including the drift from reducing message
/// arithmetic modulo t when `floor(Q/t)*t != Q`, must remain recoverable; the
/// fresh private-encryption bound is not an evaluated-noise guarantee.
pub struct BfvEvaluator<'a> {
    context: &'a BfvContext,
    level: usize,
    plaintext: DcrtPolynomial<Vec<u64>>,
}

impl<'a> BfvEvaluator<'a> {
    /// Binds one prepared level and allocates its plaintext CRT/NTT scratch once.
    ///
    /// # Panics
    /// Panics if `level` was not prepared by the context.
    #[must_use]
    pub fn new(context: &'a BfvContext, level: usize) -> Self {
        let length = context.rns_poly_len(level);
        Self {
            context,
            level,
            plaintext: DcrtPolynomial::zero(length),
        }
    }

    /// Writes the component-wise ciphertext sum.
    ///
    /// # Panics
    /// Rejects recorded context/level conflicts and incorrect complete lengths before writes.
    pub fn add_to<A, B, C>(
        &self,
        lhs: &BfvCiphertext<A>,
        rhs: &BfvCiphertext<B>,
        output: &mut BfvCiphertext<C>,
    ) where
        A: Data<Elem = u64>,
        B: Data<Elem = u64>,
        C: DataMut<Elem = u64>,
    {
        lhs.check_binding(self.context, self.level);
        rhs.check_binding(self.context, self.level);
        output.check_binding(self.context, self.level);
        let length = self.plaintext.as_ref().len();
        let (lhs0, lhs1) = lhs.c0_c1(length);
        let (rhs0, rhs1) = rhs.c0_c1(length);
        let (mut output0, mut output1) = output.c0_c1_mut(length);
        let n = self.context.parameters().poly_length().get();
        let moduli = self.context.codec(self.level).base_q().moduli();
        lhs0.add_to(&rhs0, &mut output0, n, moduli);
        lhs1.add_to(&rhs1, &mut output1, n, moduli);
    }

    /// Adds `rhs` to both components of `input` in place.
    ///
    /// # Panics
    /// Rejects recorded context/level conflicts or either incorrect length before writes.
    pub fn add_assign<A, B>(&self, input: &mut BfvCiphertext<A>, rhs: &BfvCiphertext<B>)
    where
        A: DataMut<Elem = u64>,
        B: Data<Elem = u64>,
    {
        rhs.check_binding(self.context, self.level);
        input.check_binding(self.context, self.level);
        let length = self.plaintext.as_ref().len();
        let (rhs0, rhs1) = rhs.c0_c1(length);
        let (mut input0, mut input1) = input.c0_c1_mut(length);
        let n = self.context.parameters().poly_length().get();
        let moduli = self.context.codec(self.level).base_q().moduli();
        input0.add_assign(&rhs0, n, moduli);
        input1.add_assign(&rhs1, n, moduli);
    }

    /// Writes the component-wise ciphertext difference.
    ///
    /// # Panics
    /// Rejects recorded context/level conflicts and incorrect complete lengths before writes.
    pub fn sub_to<A, B, C>(
        &self,
        lhs: &BfvCiphertext<A>,
        rhs: &BfvCiphertext<B>,
        output: &mut BfvCiphertext<C>,
    ) where
        A: Data<Elem = u64>,
        B: Data<Elem = u64>,
        C: DataMut<Elem = u64>,
    {
        lhs.check_binding(self.context, self.level);
        rhs.check_binding(self.context, self.level);
        output.check_binding(self.context, self.level);
        let length = self.plaintext.as_ref().len();
        let (lhs0, lhs1) = lhs.c0_c1(length);
        let (rhs0, rhs1) = rhs.c0_c1(length);
        let (mut output0, mut output1) = output.c0_c1_mut(length);
        let n = self.context.parameters().poly_length().get();
        let moduli = self.context.codec(self.level).base_q().moduli();
        lhs0.sub_to(&rhs0, &mut output0, n, moduli);
        lhs1.sub_to(&rhs1, &mut output1, n, moduli);
    }

    /// Subtracts `rhs` from both components of `input` in place.
    ///
    /// # Panics
    /// Rejects recorded context/level conflicts or either incorrect length before writes.
    pub fn sub_assign<A, B>(&self, input: &mut BfvCiphertext<A>, rhs: &BfvCiphertext<B>)
    where
        A: DataMut<Elem = u64>,
        B: Data<Elem = u64>,
    {
        rhs.check_binding(self.context, self.level);
        input.check_binding(self.context, self.level);
        let length = self.plaintext.as_ref().len();
        let (rhs0, rhs1) = rhs.c0_c1(length);
        let (mut input0, mut input1) = input.c0_c1_mut(length);
        let n = self.context.parameters().poly_length().get();
        let moduli = self.context.codec(self.level).base_q().moduli();
        input0.sub_assign(&rhs0, n, moduli);
        input1.sub_assign(&rhs1, n, moduli);
    }

    /// Writes the component-wise ciphertext negation.
    ///
    /// # Panics
    /// Rejects recorded context/level conflicts or either incorrect length before writes.
    pub fn neg_to<A, B>(&self, input: &BfvCiphertext<A>, output: &mut BfvCiphertext<B>)
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
        let moduli = self.context.codec(self.level).base_q().moduli();
        input0.neg_to(&mut output0, n, moduli);
        input1.neg_to(&mut output1, n, moduli);
    }

    /// Negates both ciphertext components in place.
    ///
    /// # Panics
    /// Rejects recorded context/level conflicts or an incorrect length before writes.
    pub fn neg_assign<A>(&self, input: &mut BfvCiphertext<A>)
    where
        A: DataMut<Elem = u64>,
    {
        input.check_binding(self.context, self.level);
        let (mut input0, mut input1) = input.c0_c1_mut(self.plaintext.as_ref().len());
        let n = self.context.parameters().poly_length().get();
        let moduli = self.context.codec(self.level).base_q().moduli();
        input0.neg_assign(n, moduli);
        input1.neg_assign(n, moduli);
    }

    /// Writes `input + plain`, applying this level's delta exactly once to `c0`.
    ///
    /// `plain` contains N canonical polynomial coefficients in `[0,t)`, not slots.
    /// Its unsigned/centered lift is selected by `embedding`.
    ///
    /// # Panics
    /// Recorded context/level, complete ciphertext/plaintext lengths and all
    /// plaintext values are checked before writes to output or scratch. Transform panics can modify scratch.
    pub fn add_plain_to<A, B, C>(
        &mut self,
        input: &BfvCiphertext<A>,
        plain: &Polynomial<B>,
        output: &mut BfvCiphertext<C>,
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
        self.prepare_plaintext(plain, embedding, true);
        input0.add_to(
            &self.plaintext,
            &mut output0,
            self.context.parameters().poly_length().get(),
            self.context.codec(self.level).base_q().moduli(),
        );
        output1.as_mut().copy_from_slice(input1.as_ref());
    }

    /// Adds one scaled plaintext lift to `input.c0`, retaining `input.c1`.
    /// The embedding and panic contract is [`Self::add_plain_to`]'s.
    pub fn add_plain_assign<A, B>(
        &mut self,
        input: &mut BfvCiphertext<A>,
        plain: &Polynomial<B>,
        embedding: PlaintextEmbedding,
    ) where
        A: DataMut<Elem = u64>,
        B: Data<Elem = u64>,
    {
        input.check_binding(self.context, self.level);
        let (mut input0, _) = input.c0_c1_mut(self.plaintext.as_ref().len());
        self.prepare_plaintext(plain, embedding, true);
        input0.add_assign(
            &self.plaintext,
            self.context.parameters().poly_length().get(),
            self.context.codec(self.level).base_q().moduli(),
        );
    }

    /// Multiplies both native components by an unscaled plaintext lift.
    ///
    /// This is negacyclic polynomial multiplication in `Z_t[X]/(X^N+1)`;
    /// plaintext delta is not applied. The embedding/panic contract is
    /// [`Self::add_plain_to`]'s. Complete evaluated noise must be checked separately.
    pub fn mul_plain_to<A, B, C>(
        &mut self,
        input: &BfvCiphertext<A>,
        plain: &Polynomial<B>,
        output: &mut BfvCiphertext<C>,
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
        self.prepare_plaintext(plain, embedding, false);
        let n = self.context.parameters().poly_length().get();
        let moduli = self.context.codec(self.level).base_q().moduli();
        input0.mul_to(&self.plaintext, &mut output0, n, moduli);
        input1.mul_to(&self.plaintext, &mut output1, n, moduli);
    }

    /// Multiplies both components by the unscaled lift in place.
    /// The embedding and panic contract is [`Self::mul_plain_to`]'s.
    pub fn mul_plain_assign<A, B>(
        &mut self,
        input: &mut BfvCiphertext<A>,
        plain: &Polynomial<B>,
        embedding: PlaintextEmbedding,
    ) where
        A: DataMut<Elem = u64>,
        B: Data<Elem = u64>,
    {
        input.check_binding(self.context, self.level);
        let (mut input0, mut input1) = input.c0_c1_mut(self.plaintext.as_ref().len());
        self.prepare_plaintext(plain, embedding, false);
        let n = self.context.parameters().poly_length().get();
        let moduli = self.context.codec(self.level).base_q().moduli();
        input0.mul_assign(&self.plaintext, n, moduli);
        input1.mul_assign(&self.plaintext, n, moduli);
    }

    fn validate_plaintext(&self, input: &[u64]) {
        assert_eq!(
            input.len(),
            self.context.parameters().poly_length().get(),
            "BFV plaintext length mismatch"
        );
        let t = self.context.codec(self.level).t();
        assert!(
            input.iter().all(|&value| value < t),
            "BFV plaintext coefficients must be less than t"
        );
    }

    fn prepare_plaintext<A>(
        &mut self,
        plain: &Polynomial<A>,
        embedding: PlaintextEmbedding,
        scaled: bool,
    ) where
        A: Data<Elem = u64>,
    {
        let codec = self.context.codec(self.level);
        let n = self.context.parameters().poly_length().get();
        if scaled {
            codec.encode_coeffs_to(
                plain,
                &mut CrtPolynomial(self.plaintext.as_mut()),
                embedding,
            );
        } else {
            self.validate_plaintext(plain.as_ref());
            let t = codec.t();
            let half = t.div_ceil(2);
            for (limb, &q) in self
                .plaintext
                .iter_each_modulus_mut(n)
                .zip(codec.moduli_values())
            {
                match embedding {
                    PlaintextEmbedding::Unsigned => limb.copy_from_slice(plain.as_ref()),
                    PlaintextEmbedding::Centered => {
                        for (&value, residue) in plain.as_ref().iter().zip(limb) {
                            *residue = if value < half { value } else { q - (t - value) };
                        }
                    }
                }
            }
        }
        // The context table contains the complete top basis. Transform only
        // this level's limbs rather than violating DcrtTable's full-length contract.
        for (table, limb) in self
            .context
            .table()
            .iter()
            .zip(self.plaintext.iter_each_modulus_mut(n))
        {
            table.transform_slice(limb);
        }
    }
}
