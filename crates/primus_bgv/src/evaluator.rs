use primus_data::{Data, DataMut};
use primus_ntt::NttTable;
use primus_poly::{DcrtPolynomial, Polynomial};

use crate::client::validate_plaintext;
use crate::{BgvCiphertext, BgvContext, BgvQuadraticCiphertext, PlaintextEmbedding};

/// Prepared BGV linear, plaintext and quadratic operations at one Q level.
///
/// The evaluator borrows immutable parameters/tables and owns one reusable
/// plaintext polynomial. It retains no key or RNG and allocates nothing after
/// construction. Both addition and multiplication lift plaintext without a
/// BFV Delta or another factor of p.
///
/// # Correctness
/// Ciphertexts must use this context's ordered basis, canonical NTT residues,
/// actual secret and transform convention. Matching lengths do not establish
/// these conditions. The centered integer phase after all operations must fit
/// in (-Q/2,Q/2): reducing a phase by Q can change its residue modulo p even
/// when each q_i is 1 modulo p. Parameter fresh-private bounds do not establish
/// a bound for public encryption or a complete evaluated circuit.
pub struct BgvEvaluator<'a> {
    context: &'a BgvContext,
    level: usize,
    plaintext: DcrtPolynomial<Vec<u64>>,
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

    /// Writes the component-wise ciphertext sum.
    ///
    /// # Panics
    /// Every complete input/output length is checked before any output writes.
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
        let length = self.plaintext.as_ref().len();
        let (lhs0, lhs1) = lhs.c0_c1(length);
        let (rhs0, rhs1) = rhs.c0_c1(length);
        let (mut output0, mut output1) = output.c0_c1_mut(length);
        let n = self.context.parameters().poly_length().get();
        let moduli = self.context.base_q(self.level).moduli();
        lhs0.add_to(&rhs0, &mut output0, n, moduli);
        lhs1.add_to(&rhs1, &mut output1, n, moduli);
    }

    /// Adds `rhs` to both components of `input` in place.
    ///
    /// # Panics
    /// Rejects either incorrect complete length before writes.
    pub fn add_assign<A, B>(&self, input: &mut BgvCiphertext<A>, rhs: &BgvCiphertext<B>)
    where
        A: DataMut<Elem = u64>,
        B: Data<Elem = u64>,
    {
        let length = self.plaintext.as_ref().len();
        let (rhs0, rhs1) = rhs.c0_c1(length);
        let (mut input0, mut input1) = input.c0_c1_mut(length);
        let n = self.context.parameters().poly_length().get();
        let moduli = self.context.base_q(self.level).moduli();
        input0.add_assign(&rhs0, n, moduli);
        input1.add_assign(&rhs1, n, moduli);
    }

    /// Writes the component-wise ciphertext difference.
    ///
    /// # Panics
    /// Every complete input/output length is checked before any output writes.
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
        let length = self.plaintext.as_ref().len();
        let (lhs0, lhs1) = lhs.c0_c1(length);
        let (rhs0, rhs1) = rhs.c0_c1(length);
        let (mut output0, mut output1) = output.c0_c1_mut(length);
        let n = self.context.parameters().poly_length().get();
        let moduli = self.context.base_q(self.level).moduli();
        lhs0.sub_to(&rhs0, &mut output0, n, moduli);
        lhs1.sub_to(&rhs1, &mut output1, n, moduli);
    }

    /// Subtracts `rhs` from both components of `input` in place.
    ///
    /// # Panics
    /// Rejects either incorrect complete length before writes.
    pub fn sub_assign<A, B>(&self, input: &mut BgvCiphertext<A>, rhs: &BgvCiphertext<B>)
    where
        A: DataMut<Elem = u64>,
        B: Data<Elem = u64>,
    {
        let length = self.plaintext.as_ref().len();
        let (rhs0, rhs1) = rhs.c0_c1(length);
        let (mut input0, mut input1) = input.c0_c1_mut(length);
        let n = self.context.parameters().poly_length().get();
        let moduli = self.context.base_q(self.level).moduli();
        input0.sub_assign(&rhs0, n, moduli);
        input1.sub_assign(&rhs1, n, moduli);
    }

    /// Writes the component-wise ciphertext negation.
    ///
    /// # Panics
    /// Rejects either incorrect complete length before writes.
    pub fn neg_to<A, B>(&self, input: &BgvCiphertext<A>, output: &mut BgvCiphertext<B>)
    where
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        let length = self.plaintext.as_ref().len();
        let (input0, input1) = input.c0_c1(length);
        let (mut output0, mut output1) = output.c0_c1_mut(length);
        let n = self.context.parameters().poly_length().get();
        let moduli = self.context.base_q(self.level).moduli();
        input0.neg_to(&mut output0, n, moduli);
        input1.neg_to(&mut output1, n, moduli);
    }

    /// Negates both ciphertext components in place.
    ///
    /// # Panics
    /// Rejects an incorrect complete length before writes.
    pub fn neg_assign<A>(&self, input: &mut BgvCiphertext<A>)
    where
        A: DataMut<Elem = u64>,
    {
        let (mut input0, mut input1) = input.c0_c1_mut(self.plaintext.as_ref().len());
        let n = self.context.parameters().poly_length().get();
        let moduli = self.context.base_q(self.level).moduli();
        input0.neg_assign(n, moduli);
        input1.neg_assign(n, moduli);
    }

    /// Writes `input + lift(plain)` in c0, retaining c1 unchanged.
    ///
    /// `plain` contains N canonical polynomial coefficients in `[0,p)`, not slots.
    /// Its unsigned/centered lift is selected by `embedding`.
    ///
    /// # Panics
    /// Complete ciphertext/plaintext lengths and all plaintext values are checked
    /// before writes to output or scratch. Transform panics can modify scratch.
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
        let length = self.plaintext.as_ref().len();
        let (input0, input1) = input.c0_c1(length);
        let (mut output0, mut output1) = output.c0_c1_mut(length);
        self.prepare_plaintext(plain, embedding);
        input0.add_to(
            &self.plaintext,
            &mut output0,
            self.context.parameters().poly_length().get(),
            self.context.base_q(self.level).moduli(),
        );
        output1.as_mut().copy_from_slice(input1.as_ref());
    }

    /// Adds one unscaled plaintext lift to c0, retaining c1.
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
        let (mut input0, _) = input.c0_c1_mut(self.plaintext.as_ref().len());
        self.prepare_plaintext(plain, embedding);
        input0.add_assign(
            &self.plaintext,
            self.context.parameters().poly_length().get(),
            self.context.base_q(self.level).moduli(),
        );
    }

    /// Multiplies both native components by an unscaled plaintext lift.
    ///
    /// This is negacyclic polynomial multiplication in `Z_p[X]/(X^N+1)`;
    /// No Delta or extra p scale is applied. The embedding/panic contract is
    /// [`Self::add_plain_to`]'s. Complete evaluated noise must be checked separately.
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
        let length = self.plaintext.as_ref().len();
        let (input0, input1) = input.c0_c1(length);
        let (mut output0, mut output1) = output.c0_c1_mut(length);
        self.prepare_plaintext(plain, embedding);
        let n = self.context.parameters().poly_length().get();
        let moduli = self.context.base_q(self.level).moduli();
        input0.mul_to(&self.plaintext, &mut output0, n, moduli);
        input1.mul_to(&self.plaintext, &mut output1, n, moduli);
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
        let (mut input0, mut input1) = input.c0_c1_mut(self.plaintext.as_ref().len());
        self.prepare_plaintext(plain, embedding);
        let n = self.context.parameters().poly_length().get();
        let moduli = self.context.base_q(self.level).moduli();
        input0.mul_assign(&self.plaintext, n, moduli);
        input1.mul_assign(&self.plaintext, n, moduli);
    }

    /// Writes the exact quadratic tensor of two native degree-one inputs.
    ///
    /// Output components are `[l0*r0, l0*r1+l1*r0, l1*r1]`, with phase
    /// `(l0+l1*s)*(r0+r1*s)`. There is no BFV scale-and-round. Use a prepared
    /// relinearizer to obtain a degree-one ciphertext. The complete product
    /// phase must remain in the centered recovery interval.
    ///
    /// # Panics
    /// All complete input/output lengths are checked before any output writes.
    pub fn mul_to<A, B, C>(
        &self,
        lhs: &BgvCiphertext<A>,
        rhs: &BgvCiphertext<B>,
        output: &mut BgvQuadraticCiphertext<C>,
    ) where
        A: Data<Elem = u64>,
        B: Data<Elem = u64>,
        C: DataMut<Elem = u64>,
    {
        let length = self.plaintext.as_ref().len();
        let (l0, l1) = lhs.c0_c1(length);
        let (r0, r1) = rhs.c0_c1(length);
        let (mut o0, mut o1, mut o2) = output.c0_c1_c2_mut(length);
        let n = self.context.parameters().poly_length().get();
        let moduli = self.context.base_q(self.level).moduli();
        l0.mul_to(&r0, &mut o0, n, moduli);
        l0.mul_to(&r1, &mut o1, n, moduli);
        o1.add_mul_assign(&l1, &r0, n, moduli);
        l1.mul_to(&r1, &mut o2, n, moduli);
    }

    /// Writes `[c0², 2*c0*c1, c1²]` using three polynomial products.
    ///
    /// This is the square specialization of [`Self::mul_to`], with the same
    /// representation, recovery-bound and complete-length panic contracts.
    pub fn square_to<A, B>(&self, input: &BgvCiphertext<A>, output: &mut BgvQuadraticCiphertext<B>)
    where
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        use primus_reduce::ReduceAdd;
        let length = self.plaintext.as_ref().len();
        let (c0, c1) = input.c0_c1(length);
        let (mut o0, mut o1, mut o2) = output.c0_c1_c2_mut(length);
        let n = self.context.parameters().poly_length().get();
        let moduli = self.context.base_q(self.level).moduli();
        c0.mul_to(&c0, &mut o0, n, moduli);
        c0.mul_to(&c1, &mut o1, n, moduli);
        for (limb, q) in o1.as_mut().chunks_exact_mut(n).zip(moduli) {
            for value in limb {
                *value = q.reduce_add(*value, *value);
            }
        }
        c1.mul_to(&c1, &mut o2, n, moduli);
    }

    fn prepare_plaintext<A>(&mut self, plain: &Polynomial<A>, embedding: PlaintextEmbedding)
    where
        A: Data<Elem = u64>,
    {
        let parameters = self.context.parameters();
        let n = parameters.poly_length().get();
        let p = parameters.plain_modulus().value();
        validate_plaintext(self.context, plain.as_ref());
        let half = p.div_ceil(2);
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
