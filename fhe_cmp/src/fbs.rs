use crate::{bootstrap, CmpFheParameters, SecretKeyPack};
use algebra::{
    integer::{AsInto, UnsignedInteger},
    polynomial::FieldPolynomial,
    reduce::{ReduceAddAssign, ReduceNeg, RingReduce},
    NttField,
};
use fhe_core::LweCiphertext;
use rand::{CryptoRng, Rng};

/// An evaluator for performing bootstrapping and homomorphic operations on LWE ciphertexts.
///
/// This struct encapsulates the necessary evaluation key for bootstrapping.
///
/// # Type Parameters
/// - `C`: An unsigned integer type representing ciphertext coefficients.
/// - `LweModulus`: A modulus type implementing [`RingReduce`] for `C`.
/// - `Q`: A field type (typically for NTT operations) implementing [`NttField`].
#[derive(Clone)]
pub struct Mbsextract<C: UnsignedInteger, LweModulus: RingReduce<C>, Q: NttField> {
    /// An evaluation key used for various bootstrapping operations.
    ek: bootstrap::EvaluationKey<C, LweModulus, Q>,
}

impl<C, LweModulus, Q> Mbsextract<C, LweModulus, Q>
where
    C: UnsignedInteger,
    LweModulus: RingReduce<C>,
    Q: NttField,
{
    /// Creates a new `Mbsextract` by generating a bootstrapping evaluation key from
    /// a provided secret key pack. A cryptographically secure random number generator
    /// is also required to sample randomness when building the evaluation key.
    ///
    /// # Parameters
    /// - `sk`: A reference to a [`SecretKeyPack`] containing LWE secret key information.
    /// - `rng`: A random number generator implementing [`Rng`] + [`CryptoRng`].
    ///
    /// # Returns
    /// A new `Mbsextract` instance containing the generated evaluation key.
    #[inline]
    pub fn new<R: Rng + CryptoRng>(sk: &SecretKeyPack<C, LweModulus, Q>, rng: &mut R) -> Self {
        Self {
            ek: bootstrap::EvaluationKey::new(sk, rng),
        }
    }

    /// Returns a reference to the cryptographic parameter set (e.g., dimensions, moduli, etc.)
    /// associated with this evaluator.
    ///
    /// # Returns
    /// A reference to a [`CmpFheParameters`] object describing the encryption parameters.
    #[inline]
    pub fn parameters(&self) -> &CmpFheParameters<C, LweModulus, Q> {
        self.ek.parameters()
    }

    /// Performs a bootstrapping operation on an LWE ciphertext `c` using a lookup table `lut`.
    ///
    /// This method applies a typical TFHE-style bootstrapping where the ciphertext is
    /// refreshed and the function encoded in `lut` is homomorphically applied.
    ///
    /// # Parameters
    /// - `c`: The LWE ciphertext to be bootstrapped.
    /// - `lut`: A polynomial encoding a lookup table for the function to be applied.
    ///
    /// # Returns
    /// A refreshed LWE ciphertext after bootstrapping.
    #[inline]
    pub fn bootstrap(&self, c: LweCiphertext<C>, lut: FieldPolynomial<Q>) -> LweCiphertext<C> {
        self.ek.bootstrap(c, lut)
    }

    /// Computes the "MSB gate" on a provided LWE ciphertext.
    ///
    /// Internally, this method calls the evaluation key’s [`msb_gate`] implementation,
    /// which roughly extracts the most significant bit information of the plaintext
    /// under some modular representation.
    ///
    /// # Parameters
    /// - `c`: A reference to the LWE ciphertext from which the MSB is to be extracted.
    ///
    /// # Returns
    /// A new LWE ciphertext containing the result of the MSB extraction.
    pub fn msb_gate<M>(&self, c: &LweCiphertext<C>) -> LweCiphertext<C>
    where
        M: Copy + ReduceNeg<C, Output = C> + ReduceAddAssign<C>,
    {
        self.ek.msb_gate::<M>(c)
    }

    /// Performs an "ideal" MSB gate operation, which includes an internal scaling step.
    ///
    /// This function is similar to [`msb_gate`] but allows for a specific scaling factor
    /// (`scale_bits`) to adapt to the plaintext space’s size.
    ///
    /// # Parameters
    /// - `c`: A reference to the LWE ciphertext.
    /// - `scale_bits`: Number of bits to scale for the MSB extraction.
    ///
    /// # Returns
    /// A newly created LWE ciphertext containing the processed MSB information.
    pub fn ide_msb_gate<M>(&self, c: &LweCiphertext<C>, scale_bits: u32) -> LweCiphertext<C>
    where
        M: Copy + ReduceNeg<C, Output = C> + ReduceAddAssign<C>,
    {
        self.ek.ide_msb_gate::<M>(c, scale_bits)
    }

    /// Converts an arithmetic-based ciphertext representation into a log-based one.
    ///
    /// This method leverages arithmetic-to-log conversion defined by the evaluation key
    /// to transform how the ciphertext’s message is encoded.
    ///
    /// # Parameters
    /// - `c`: The LWE ciphertext to convert.
    ///
    /// # Returns
    /// A transformed LWE ciphertext in logarithmic representation.
    pub fn ari_to_log<M>(&self, c: &LweCiphertext<C>) -> LweCiphertext<C>
    where
        M: Copy + ReduceNeg<C, Output = C> + ReduceAddAssign<C>,
    {
        self.ek.ari_to_log::<M>(c)
    }

    /// Extracts the 5 most significant bits (MSBs) of the plaintext enclosed within
    /// an LWE ciphertext.
    ///
    /// This method simply calls [`msb_gate`] internally to obtain the relevant bits.
    ///
    /// # Parameters
    /// - `c`: A reference to the ciphertext whose MSBs are to be extracted.
    ///
    /// # Returns
    /// A new ciphertext that represents these 5 MSBs in encrypted form.
    pub fn extractmsb5<M>(&self, c: &LweCiphertext<C>) -> LweCiphertext<C>
    where
        M: Copy + ReduceNeg<C, Output = C> + ReduceAddAssign<C>,
    {
        self.msb_gate::<M>(&c.clone())
    }

    /// Extracts 9 bits (in particular, splits a 4-bit and 5-bit portion) from the
    /// specified LWE ciphertext.
    ///
    /// The process involves:
    /// 1. Shifting the ciphertext to isolate the higher bits.
    /// 2. Extracting the MSB gate result of the shifted ciphertext.
    /// 3. Subtracting this intermediate result from the shifted ciphertext.
    /// 4. Applying an “ideal” MSB gate to rescale back.
    /// 5. Subtracting the rescaled ciphertext from the original input.
    /// 6. Invoking [`extractmsb5`] to finalize the 5-bit portion, thereby combining
    ///    the partial extraction steps into a 9-bit extraction overall.
    ///
    /// # Parameters
    /// - `c`: The ciphertext from which 9 bits are to be extracted.
    /// - `lwe_cipher_modulus`: A modulus object implementing [`RingReduce`] for type `C`.
    /// - `plain_bits`: The total number of bits for the plaintext space. Assumes the last
    ///   9 bits are relevant for extraction.
    ///
    /// # Returns
    /// A ciphertext that corresponds to the 9-bit extraction result.
    pub fn extractmsb9<M>(
        &self,
        c: &LweCiphertext<C>,
        lwe_cipher_modulus: impl RingReduce<C>,
        plain_bits: u32,
    ) -> LweCiphertext<C>
    where
        M: Copy + ReduceNeg<C, Output = C> + ReduceAddAssign<C>,
    {
        // Clone the original ciphertext for manipulation.
        let mut cipher_in = c.clone();

        // Prepare a second clone (`cipher1`) to receive the bit-shifted result.
        let mut cipher1 = c.clone();

        // Compute how many bits to shift. For example, if `plain_bits` is 9 and we already
        // accounted for 5 bits, shift by 4 bits (9 - 5 = 4).
        let shift_bits: u64 = (plain_bits - 5).as_into();
        let shift_value: C = (1u64 << shift_bits).as_into();

        // Multiply each coefficient in the ciphertext by `2^(shift_bits)`, effectively
        // performing a left shift modulo the LWE ciphertext modulus.
        for i in 0..self.parameters().lwe_dimension() {
            cipher1.a_mut()[i] = lwe_cipher_modulus.reduce_mul(cipher_in.a_mut()[i], shift_value);
        }

        // Shift the constant term (b) in the same manner.
        *cipher1.b_mut() = lwe_cipher_modulus.reduce_mul(*cipher_in.b_mut(), shift_value);

        // Apply MSB gate to the shifted ciphertext, yielding an intermediate ciphertext
        // containing sign/MSB information.
        let cipher2 = self.msb_gate::<M>(&cipher1.clone());

        // Subtract `cipher2` from `cipher1` to isolate specific bits of interest in `cipher3`.
        let mut cipher3 = cipher1.clone();
        for i in 0..self.parameters().lwe_dimension() {
            cipher3.a_mut()[i] = lwe_cipher_modulus.reduce_sub(cipher1.a()[i], cipher2.a()[i]);
        }
        *cipher3.b_mut() = lwe_cipher_modulus.reduce_sub(cipher1.b(), cipher2.b());

        // Apply an "ideal" MSB gate with `plain_bits` scaling to bring the shifted result back
        // into an appropriate range.
        let cipher4 = self.ide_msb_gate::<M>(&cipher3.clone(), plain_bits);

        // Subtract the rescaled portion (`cipher4`) from the original ciphertext to finalize
        // the partial extraction. This difference is stored in `cipher5`.
        let cipher5 = c.sub_reduce_component_wise_ref(&cipher4, lwe_cipher_modulus);

        // Finally, call `extractmsb5` on the difference to pick out the 5 MSBs. This step
        // integrates everything and yields the final 9-bit extraction result.
        self.extractmsb5::<M>(&cipher5.clone())
    }

    /// Extracts 13 bits from the given ciphertext by performing multi-step MSB extractions.
    ///
    /// This method follows a similar procedure as smaller-bit extractions but extends it to
    /// retrieve a total of 13 MSBs. The internal steps are as follows:
    ///
    /// 1. **Clone** the original ciphertext into `cipher_in` and `cipher1` for manipulation.
    /// 2. **Compute Shift**:  
    ///    - Determine how many bits to shift by `(plain_bits - 5)`, and build the `shift_value`.
    /// 3. **Left-Shift** `cipher1`:  
    ///    - Multiply each coefficient and the scalar part by `2^(shift_bits)`, reducing modulo
    ///      the LWE ciphertext modulus.
    /// 4. **MSB Gate**:  
    ///    - Apply `msb_gate` to the shifted ciphertext (`cipher1`) to obtain its MSB information
    ///      in a new ciphertext (`cipher2`).
    /// 5. **Subtract** the MSB ciphertext from the shifted ciphertext to isolate relevant bits:  
    ///    - `cipher3 = cipher1 - cipher2` (component-wise).
    /// 6. **Ideal MSB Gate**:  
    ///    - Rescale `cipher3` by calling `ide_msb_gate`, producing `cipher4`.
    /// 7. **Combine** with Original Ciphertext:  
    ///    - Subtract `cipher4` from the original ciphertext `c` to form the partially extracted
    ///      bits in `cipher5`.
    /// 8. **Recursive Extraction** (to reach 13 bits):  
    ///    - Calls `extractmsb9` on `cipher5` (with updated `plain_bits - 4`) to progressively
    ///      incorporate an additional block of bits.
    ///
    /// # Parameters
    /// - `c`: The ciphertext from which 13 MSBs are extracted.
    /// - `lwe_cipher_modulus`: The modulus used for LWE ciphertext operations.
    /// - `plain_bits`: The total number of plaintext bits; assumes we are extracting a specific
    ///   13-bit segment from that range.
    ///
    /// # Returns
    /// A ciphertext corresponding to the 13-bit extraction result.
    ///
    /// # Type Parameters
    /// - `M`: A type bound that includes `Copy`, `ReduceNeg`, and `ReduceAddAssign`, indicating
    ///   the supported arithmetic operations required by the bootstrapping.
    pub fn extractmsb13<M>(
        &self,
        c: &LweCiphertext<C>,
        lwe_cipher_modulus: impl RingReduce<C>,
        plain_bits: u32,
    ) -> LweCiphertext<C>
    where
        M: Copy + ReduceNeg<C, Output = C> + ReduceAddAssign<C>,
    {
        let mut cipher_in = c.clone();

        // 1. Prepare a cloned ciphertext to shift the bits (cipher1).
        let mut cipher1 = c.clone();

        // 2. Calculate how many bits to shift, then build the shift value.
        let shift_bits: u64 = (plain_bits - 5u32).as_into();
        let shift_value: C = (1u64 << shift_bits).as_into();

        // 3. Left-shift cipher1’s coefficients and scalar part.
        for i in 0..self.parameters().lwe_dimension() {
            cipher1.a_mut()[i] = lwe_cipher_modulus.reduce_mul(cipher_in.a_mut()[i], shift_value);
        }
        *cipher1.b_mut() = lwe_cipher_modulus.reduce_mul(*cipher_in.b_mut(), shift_value);

        // 4. Apply MSB gate to the shifted ciphertext, capturing MSB info in cipher2.
        let cipher2 = self.msb_gate::<M>(&cipher1.clone());

        // 5. Subtract cipher2 from cipher1 to isolate bits in cipher3.
        let mut cipher3 = cipher1.clone();
        for i in 0..self.parameters().lwe_dimension() {
            cipher3.a_mut()[i] = lwe_cipher_modulus.reduce_sub(cipher1.a()[i], cipher2.a()[i]);
        }
        *cipher3.b_mut() = lwe_cipher_modulus.reduce_sub(cipher1.b(), cipher2.b());

        // 6. Rescale cipher3 using the ideal MSB gate.
        let cipher4 = self.ide_msb_gate::<M>(&cipher3.clone(), plain_bits);

        // 7. Subtract the result from the original ciphertext to finalize intermediate bits.
        let cipher5 = c.sub_reduce_component_wise_ref(&cipher4, lwe_cipher_modulus);

        // 8. Call extractmsb9 on cipher5 with adjusted plain_bits to fully obtain 13 bits.
        self.extractmsb9::<M>(&cipher5.clone(), lwe_cipher_modulus, plain_bits - 4u32)
    }

    /// Extracts 17 bits from the given ciphertext by chaining multiple MSB extraction operations.
    /// # Parameters
    /// - `c`: The ciphertext from which 17 MSBs are extracted.
    /// - `lwe_cipher_modulus`: The modulus for ciphertext operations.
    /// - `plain_bits`: The total plaintext bits, from which we isolate 17 MSBs.
    ///
    /// # Returns
    /// A ciphertext capturing the 17 extracted bits.
    ///
    /// # Type Parameters
    /// - `M`: A type that implements necessary reduce/negation traits for the MSB gate.
    pub fn extractmsb17<M>(
        &self,
        c: &LweCiphertext<C>,
        lwe_cipher_modulus: impl RingReduce<C>,
        plain_bits: u32,
    ) -> LweCiphertext<C>
    where
        M: Copy + ReduceNeg<C, Output = C> + ReduceAddAssign<C>,
    {
        let mut cipher_in = c.clone();
        let mut cipher1 = c.clone();

        let shift_bits: u64 = (plain_bits - 5u32).as_into();
        let shift_value: C = (1u64 << shift_bits).as_into();

        for i in 0..self.parameters().lwe_dimension() {
            cipher1.a_mut()[i] = lwe_cipher_modulus.reduce_mul(cipher_in.a_mut()[i], shift_value);
        }
        *cipher1.b_mut() = lwe_cipher_modulus.reduce_mul(*cipher_in.b_mut(), shift_value);

        let cipher2 = self.msb_gate::<M>(&cipher1.clone());

        let mut cipher3 = cipher1.clone();
        for i in 0..self.parameters().lwe_dimension() {
            cipher3.a_mut()[i] = lwe_cipher_modulus.reduce_sub(cipher1.a()[i], cipher2.a()[i]);
        }
        *cipher3.b_mut() = lwe_cipher_modulus.reduce_sub(cipher1.b(), cipher2.b());

        let cipher4 = self.ide_msb_gate::<M>(&cipher3.clone(), plain_bits);
        let cipher5 = c.sub_reduce_component_wise_ref(&cipher4, lwe_cipher_modulus);

        // Recursively extract 13 bits from the updated ciphertext to reach 17 bits overall.
        self.extractmsb13::<M>(&cipher5.clone(), lwe_cipher_modulus, plain_bits - 4u32)
    }

    /// Extracts 21 bits from the given ciphertext by chaining multiple extractions.
    ///
    /// The procedure is an extension of the smaller MSB gate extraction, now repeated enough
    /// times to accumulate 21 bits overall.
    /// # Parameters
    /// - `c`: Original ciphertext from which 21 bits are extracted.
    /// - `lwe_cipher_modulus`: Modulus used for LWE ciphertext operations.
    /// - `plain_bits`: Total plaintext bit-length.
    ///
    /// # Returns
    /// A ciphertext containing 21 extracted bits.
    ///
    /// # Type Parameters
    /// - `M`: Type bound that requires copying and certain arithmetic reductions for the MSB gate.
    pub fn extractmsb21<M>(
        &self,
        c: &LweCiphertext<C>,
        lwe_cipher_modulus: impl RingReduce<C>,
        plain_bits: u32,
    ) -> LweCiphertext<C>
    where
        M: Copy + ReduceNeg<C, Output = C> + ReduceAddAssign<C>,
    {
        let mut cipher_in = c.clone();
        let mut cipher1 = c.clone();

        let shift_bits: u64 = (plain_bits - 5u32).as_into();
        let shift_value: C = (1u64 << shift_bits).as_into();

        for i in 0..self.parameters().lwe_dimension() {
            cipher1.a_mut()[i] = lwe_cipher_modulus.reduce_mul(cipher_in.a_mut()[i], shift_value);
        }
        *cipher1.b_mut() = lwe_cipher_modulus.reduce_mul(*cipher_in.b_mut(), shift_value);

        let cipher2 = self.msb_gate::<M>(&cipher1.clone());

        let mut cipher3 = cipher1.clone();
        for i in 0..self.parameters().lwe_dimension() {
            cipher3.a_mut()[i] = lwe_cipher_modulus.reduce_sub(cipher1.a()[i], cipher2.a()[i]);
        }
        *cipher3.b_mut() = lwe_cipher_modulus.reduce_sub(cipher1.b(), cipher2.b());

        let cipher4 = self.ide_msb_gate::<M>(&cipher3.clone(), plain_bits);
        let cipher5 = c.sub_reduce_component_wise_ref(&cipher4, lwe_cipher_modulus);

        // Recursively extract 17 bits from cipher5, culminating in 21 bits total.
        self.extractmsb17::<M>(&cipher5.clone(), lwe_cipher_modulus, plain_bits - 4u32)
    }

    /// Extracts 25 bits from the given ciphertext by chaining several MSB extractions.
    /// # Parameters
    /// - `c`: The input LWE ciphertext.
    /// - `lwe_cipher_modulus`: The modulus used for ring reduction on ciphertext components.
    /// - `plain_bits`: The total number of bits in the underlying plaintext message space.
    ///
    /// # Returns
    /// A new LWE ciphertext containing the extracted 25 bits.
    ///
    /// # Type Parameters
    /// - `M`: A trait bound providing necessary reduction/negation operations.
    pub fn extractmsb25<M>(
        &self,
        c: &LweCiphertext<C>,
        lwe_cipher_modulus: impl RingReduce<C>,
        plain_bits: u32,
    ) -> LweCiphertext<C>
    where
        M: Copy + ReduceNeg<C, Output = C> + ReduceAddAssign<C>,
    {
        let mut cipher_in = c.clone();
        let mut cipher1 = c.clone();

        // Calculate shift details: shifting by (plain_bits - 5) bits.
        let shift_bits: u64 = (plain_bits - 5u32).as_into();
        let shift_value: C = (1u64 << shift_bits).as_into();

        // Perform left-shifting (multiplying) of each coefficient and the scalar part by 2^(shift_bits).
        for i in 0..self.parameters().lwe_dimension() {
            cipher1.a_mut()[i] = lwe_cipher_modulus.reduce_mul(cipher_in.a_mut()[i], shift_value);
        }
        *cipher1.b_mut() = lwe_cipher_modulus.reduce_mul(*cipher_in.b_mut(), shift_value);

        // Apply MSB gate to capture the most significant bit of the shifted ciphertext.
        let cipher2 = self.msb_gate::<M>(&cipher1.clone());

        // Subtract the MSB portion from the shifted ciphertext.
        let mut cipher3 = cipher1.clone();
        for i in 0..self.parameters().lwe_dimension() {
            cipher3.a_mut()[i] = lwe_cipher_modulus.reduce_sub(cipher1.a()[i], cipher2.a()[i]);
        }
        *cipher3.b_mut() = lwe_cipher_modulus.reduce_sub(cipher1.b(), cipher2.b());

        // Use the "ideal" MSB gate to rescale the result.
        let cipher4 = self.ide_msb_gate::<M>(&cipher3.clone(), plain_bits);

        // Subtract the rescaled portion from the original ciphertext to isolate bits.
        let cipher5 = c.sub_reduce_component_wise_ref(&cipher4, lwe_cipher_modulus);

        // Recursively extract 21 bits from `cipher5` to complete the 25-bit extraction.
        self.extractmsb21::<M>(&cipher5.clone(), lwe_cipher_modulus, plain_bits - 4u32)
    }

    /// Extracts 29 bits from the given ciphertext by extending the MSB extraction procedure.
    /// # Parameters
    /// - `c`: The LWE ciphertext to be processed.
    /// - `lwe_cipher_modulus`: The modulus for LWE operations.
    /// - `plain_bits`: Total bits of the underlying plaintext.
    ///
    /// # Returns
    /// A new ciphertext embedding the 29 extracted bits.
    pub fn extractmsb29<M>(
        &self,
        c: &LweCiphertext<C>,
        lwe_cipher_modulus: impl RingReduce<C>,
        plain_bits: u32,
    ) -> LweCiphertext<C>
    where
        M: Copy + ReduceNeg<C, Output = C> + ReduceAddAssign<C>,
    {
        let mut cipher_in = c.clone();
        let mut cipher1 = c.clone();

        let shift_bits: u64 = (plain_bits - 5u32).as_into();
        let shift_value: C = (1u64 << shift_bits).as_into();

        for i in 0..self.parameters().lwe_dimension() {
            cipher1.a_mut()[i] = lwe_cipher_modulus.reduce_mul(cipher_in.a_mut()[i], shift_value);
        }
        *cipher1.b_mut() = lwe_cipher_modulus.reduce_mul(*cipher_in.b_mut(), shift_value);

        let cipher2 = self.msb_gate::<M>(&cipher1.clone());

        let mut cipher3 = cipher1.clone();
        for i in 0..self.parameters().lwe_dimension() {
            cipher3.a_mut()[i] = lwe_cipher_modulus.reduce_sub(cipher1.a()[i], cipher2.a()[i]);
        }
        *cipher3.b_mut() = lwe_cipher_modulus.reduce_sub(cipher1.b(), cipher2.b());

        let cipher4 = self.ide_msb_gate::<M>(&cipher3.clone(), plain_bits);
        let cipher5 = c.sub_reduce_component_wise_ref(&cipher4, lwe_cipher_modulus);

        // Recursively call extractmsb25 to complete the extraction to 29 bits.
        self.extractmsb25::<M>(&cipher5.clone(), lwe_cipher_modulus, plain_bits - 4u32)
    }

    /// Extracts 33 bits from the given ciphertext.
    ///
    /// The logic follows the same pattern of shifting, extracting MSBs, rescaling,
    /// subtracting from the original ciphertext, and then performing another MSB extraction
    /// recursively. This time, it calls `extractmsb29` after preparing the intermediary.
    ///
    /// # Parameters
    /// - `c`: Original LWE ciphertext.
    /// - `lwe_cipher_modulus`: Modulus for LWE ring operations.
    /// - `plain_bits`: The total number of bits in the plaintext domain.
    ///
    /// # Returns
    /// A ciphertext that contains 33 MSBs of the original message.
    pub fn extractmsb33<M>(
        &self,
        c: &LweCiphertext<C>,
        lwe_cipher_modulus: impl RingReduce<C>,
        plain_bits: u32,
    ) -> LweCiphertext<C>
    where
        M: Copy + ReduceNeg<C, Output = C> + ReduceAddAssign<C>,
    {
        let mut cipher_in = c.clone();
        let mut cipher1 = c.clone();

        let shift_bits: u64 = (plain_bits - 5u32).as_into();
        let shift_value: C = (1u64 << shift_bits).as_into();

        for i in 0..self.parameters().lwe_dimension() {
            cipher1.a_mut()[i] = lwe_cipher_modulus.reduce_mul(cipher_in.a_mut()[i], shift_value);
        }
        *cipher1.b_mut() = lwe_cipher_modulus.reduce_mul(*cipher_in.b_mut(), shift_value);

        let cipher2 = self.msb_gate::<M>(&cipher1.clone());

        let mut cipher3 = cipher1.clone();
        for i in 0..self.parameters().lwe_dimension() {
            cipher3.a_mut()[i] = lwe_cipher_modulus.reduce_sub(cipher1.a()[i], cipher2.a()[i]);
        }
        *cipher3.b_mut() = lwe_cipher_modulus.reduce_sub(cipher1.b(), cipher2.b());

        let cipher4 = self.ide_msb_gate::<M>(&cipher3.clone(), plain_bits);
        let cipher5 = c.sub_reduce_component_wise_ref(&cipher4, lwe_cipher_modulus);

        // Recursively call extractmsb29 to finalize the 33-bit extraction.
        self.extractmsb29::<M>(&cipher5.clone(), lwe_cipher_modulus, plain_bits - 4u32)
    }

    /// A convenience function to homomorphically extract the MSB portion of a ciphertext,
    /// selecting the appropriate extraction method based on the number of `plain_bits`.
    ///
    /// # Operation
    /// - If `plain_bits` is **≤ 6**, calls `extractmsb5`.
    /// - If **≤ 9**, calls `extractmsb9`.
    /// - If **≤ 13**, calls `extractmsb13`.
    /// - If **≤ 17**, calls `extractmsb17`.
    /// - If **≤ 21**, calls `extractmsb21`.
    /// - If **≤ 25**, calls `extractmsb25`.
    /// - If **≤ 29**, calls `extractmsb29`.
    /// - If **≤ 33**, calls `extractmsb33`.
    /// - Otherwise, it panics with an error.
    ///
    /// This switch-case style logic centralizes MSB extraction, making it easier to handle
    /// varying plaintext bit sizes from a single API entry point.
    ///
    /// # Parameters
    /// - `c`: The ciphertext from which we want to extract the MSB (or a range of bits).
    /// - `plain_bits`: The total bit width of the underlying plaintext.
    ///
    /// # Returns
    /// A ciphertext containing the extracted MSB segment.
    ///
    /// # Type Parameters
    /// - `M`: A type implementing the necessary reduce/negation traits used in bootstrapping.
    pub fn hommsb<M>(&self, c: &LweCiphertext<C>, plain_bits: u32) -> LweCiphertext<C>
    where
        M: Copy + ReduceNeg<C, Output = C> + ReduceAddAssign<C>,
    {
        let parameters = self.parameters();
        let cipher_modulus = parameters.lwe_cipher_modulus();

        if plain_bits <= 6u32 {
            // Extract up to 5 bits
            self.extractmsb5::<M>(c)
        } else if plain_bits <= 9u32 {
            self.extractmsb9::<M>(c, cipher_modulus, plain_bits)
        } else if plain_bits <= 13u32 {
            self.extractmsb13::<M>(c, cipher_modulus, plain_bits)
        } else if plain_bits <= 17u32 {
            self.extractmsb17::<M>(c, cipher_modulus, plain_bits)
        } else if plain_bits <= 21u32 {
            self.extractmsb21::<M>(c, cipher_modulus, plain_bits)
        } else if plain_bits <= 25u32 {
            self.extractmsb25::<M>(c, cipher_modulus, plain_bits)
        } else if plain_bits <= 29u32 {
            self.extractmsb29::<M>(c, cipher_modulus, plain_bits)
        } else if plain_bits <= 33u32 {
            self.extractmsb33::<M>(c, cipher_modulus, plain_bits)
        } else {
            panic!("Error: plain_bits out of range");
        }
    }
}
