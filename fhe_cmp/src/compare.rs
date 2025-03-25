use algebra::{
    integer::UnsignedInteger, reduce::{ModulusValue,ReduceAddAssign, ReduceNeg, RingReduce}, NttField
};
use fhe_core::LweCiphertext;
use rand::{CryptoRng, Rng};
use crate::{Mbsextract, CmpFheParameters, SecretKeyPack};

/// Evaluator struct for performing bootstrapping and homomorphic operations.
/// 
/// This struct encapsulates an evaluation key used during the bootstrapping procedure.
#[derive(Clone)]
pub struct FheCompare<C: UnsignedInteger, LweModulus: RingReduce<C>, Q: NttField> {
    fbs:Mbsextract<C,LweModulus,Q>
}

impl<C: UnsignedInteger, LweModulus: RingReduce<C>, Q: NttField> FheCompare<C,LweModulus,Q> {
    // ---------------------------------------------------------------------------------------------
    // Constructor
    // ---------------------------------------------------------------------------------------------

    /// Creates a new `FheCompare` instance with a given secret key pack and random generator.
    ///
    /// # Arguments
    ///
    /// * `sk` - A reference to a `SecretKeyPack` containing secret keys and associated parameters.
    /// * `rng` - A mutable reference to a random number generator implementing both `Rng` and `CryptoRng`.
    ///
    /// # Returns
    ///
    /// A newly instantiated `FheCompare` object that can perform various homomorphic operations.
    #[inline]
    pub fn new<R: Rng + CryptoRng>(
        sk: &SecretKeyPack<C,LweModulus,Q>,
        rng: &mut R,
    ) -> Self {
        Self {
            fbs:Mbsextract::new(sk,rng),
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Accessor
    // ---------------------------------------------------------------------------------------------

    /// Returns a reference to the comparison (FHE) parameters.
    ///
    /// These parameters include the cipher modulus details, polynomial degree,
    /// and other cryptographic settings required for homomorphic operations.
    #[inline]
    pub fn parameters(&self) -> &CmpFheParameters<C, LweModulus, Q> {
        self.fbs.parameters()
    }
// ---------------------------------------------------------------------------------------------
    // Utility Methods
    // ---------------------------------------------------------------------------------------------

    /// Converts an LWE ciphertext from its arithmetic domain representation to a
    /// logarithmic or gate-friendly representation.
    ///
    /// Some homomorphic operations, especially logical gates or bit-extraction,
    /// may require different internal representations of the ciphertext. This
    /// method leverages internal bootstrapping to achieve that transformation.
    ///
    /// # Type Parameters
    /// - `M`: A type parameter providing modular arithmetic traits (`ReduceNeg`, `ReduceAddAssign`).
    ///
    /// # Arguments
    /// - `c`: The ciphertext to be converted.
    ///
    /// # Returns
    ///
    /// A new ciphertext suitable for subsequent logical or MSB-related operations.
    pub fn ari_to_log<M>(&self, c: &LweCiphertext<C>) -> LweCiphertext<C>
    where
        M: Copy + ReduceNeg<C, Output = C> + ReduceAddAssign<C>,
    {
        self.fbs.ari_to_log::<M>(c)
    }

    /// Extracts the most significant bit (MSB) from an encrypted integer of a known bit length.
    ///
    /// This uses the functional bootstrapping circuit in `Mbsextract` to isolate
    /// the highest-order bit of an encrypted integer, represented by `plain_bits`.
    ///
    /// # Type Parameters
    /// - `M`: A type parameter for modular arithmetic operations.
    ///
    /// # Arguments
    /// - `c`: The ciphertext from which to extract the MSB.
    /// - `plain_bits`: The total number of bits in the original plaintext.
    ///
    /// # Returns
    ///
    /// A ciphertext whose decrypted value is the MSB of the original integer (`0` or `1`).
    pub fn hommsb<M>(&self, c: &LweCiphertext<C>, plain_bits: u32) -> LweCiphertext<C>
    where
        M: Copy + ReduceNeg<C, Output = C> + ReduceAddAssign<C>,
    {
        let res = self.fbs.hommsb::<M>(c, plain_bits);
        res
    }
    // ---------------------------------------------------------------------------------------------
    // Boolean-like Operations
    // ---------------------------------------------------------------------------------------------

    /// Computes a logical NOT on a boolean ciphertext.
    ///
    /// This operation interprets the ciphertext as either 0 or 1 under mod 2,
    /// then applies a negation in the ciphertext domain. Internally, it modifies
    /// the bias to flip the bit.
    ///
    /// # Arguments
    /// - `c`: The ciphertext to invert.
    ///
    /// # Returns
    ///
    /// A ciphertext whose decrypted bit is the logical negation of the original (`1 - x`).
    pub fn homnot(&self, c: &LweCiphertext<C>) -> LweCiphertext<C> {
        let parameters = self.parameters();
        let cipher_modulus = parameters.lwe_cipher_modulus();

        // Negate the ciphertext under the modulus.
        let mut neg = c.neg_reduce(cipher_modulus);

        // Shift the bias to flip the bit.
        match parameters.lwe_cipher_modulus_value() {
            ModulusValue::Native => {
                // Use powers of 2 directly from the type.
                cipher_modulus.reduce_add_assign(neg.b_mut(), C::ONE << (C::BITS - 2));
                cipher_modulus.reduce_add_assign(neg.b_mut(), C::ONE << (C::BITS - 6));
            }
            ModulusValue::PowerOf2(q)
            | ModulusValue::Prime(q)
            | ModulusValue::Others(q) => {
                cipher_modulus.reduce_add_assign(neg.b_mut(), q >> 2u32);
                cipher_modulus.reduce_add_assign(neg.b_mut(), q >> 6u32);
            }
        }

        neg
    }

    /// Computes a logical AND between two boolean ciphertexts.
    ///
    /// First, both ciphertexts are converted to a suitable domain (via `ari_to_log`),
    /// then combined in a way that yields a bitwise AND. Internally, a special
    /// gating method (`msb_gate`) is used to refine the result.
    ///
    /// # Type Parameters
    /// - `M`: A type parameter for modular arithmetic operations.
    ///
    /// # Arguments
    /// - `c1`: The first boolean ciphertext.
    /// - `c2`: The second boolean ciphertext.
    ///
    /// # Returns
    ///
    /// A ciphertext whose decrypted bit is `1` if both inputs are `1`, otherwise `0`.
    pub fn homand<M>(&self, c1: &LweCiphertext<C>, c2: &LweCiphertext<C>) -> LweCiphertext<C>
    where
        M: Copy + ReduceNeg<C, Output = C> + ReduceAddAssign<C>,
    {
        let parameters = self.parameters();
        let cipher_modulus = parameters.lwe_cipher_modulus();

        // Extract the raw modulus value.
        let val = match parameters.lwe_cipher_modulus_value() {
            ModulusValue::Native => {
                // Could raise an error here; returning default if needed.
                C::default()
            }
            ModulusValue::PowerOf2(v)
            | ModulusValue::Prime(v)
            | ModulusValue::Others(v) => v,
        };

        // Convert each ciphertext into a log-friendly representation.
        let cipher_1 = self.fbs.ari_to_log::<M>(&c1.clone());
        let cipher_2 = self.fbs.ari_to_log::<M>(&c2.clone());

        // Combine them (through addition or partial sub) before applying the msb_gate.
        let mut add_enc = cipher_2.add_reduce_component_wise(&cipher_1, cipher_modulus);
        cipher_modulus.reduce_add_assign(add_enc.b_mut(), val >> 3u32);

        let output = self.fbs.msb_gate::<M>(&add_enc);
        output
    }

    // ---------------------------------------------------------------------------------------------
    // Comparison Operations
    // ---------------------------------------------------------------------------------------------

    /// Produces a ciphertext indicating whether `c1` > `c2`.
    ///
    /// Internally, this calculates `c2 - c1`, then extracts the MSB. If `c2 - c1` is negative,
    /// the MSB is 1, indicating `c1` is greater than `c2`.
    ///
    /// # Type Parameters
    /// - `M`: A type parameter for modular arithmetic operations.
    ///
    /// # Arguments
    /// - `c1`: The first ciphertext.
    /// - `c2`: The second ciphertext.
    /// - `plain_bits`: The bit-length of the plaintext data.
    ///
    /// # Returns
    ///
    /// A ciphertext decrypting to `1` if `c1` > `c2`, otherwise `0`.
    pub fn greater_than<M>(&self, c1: &LweCiphertext<C>, c2: &LweCiphertext<C>, plain_bits: u32) -> LweCiphertext<C>
    where
        M: Copy + ReduceNeg<C, Output = C> + ReduceAddAssign<C>,
    {
        // Compute (c2 - c1) then extract the MSB.
        let parameters = self.parameters();
        let cipher_modulus = parameters.lwe_cipher_modulus();

        let cipher_1 = c1.clone();
        let cipher_2 = c2.clone();
        let sub_enc = cipher_2.sub_reduce_component_wise(&cipher_1, cipher_modulus);

        let output = self.hommsb::<M>(&sub_enc, plain_bits);
        output
    }

    /// Produces a ciphertext indicating whether `c1` >= `c2`.
    ///
    /// Internally, this is computed as `NOT( greater_than(c2, c1) )`.
    /// If `c2` > `c1`, then `c1 >= c2` is false, and vice versa.
    ///
    /// # Type Parameters
    /// - `M`: A type parameter for modular arithmetic operations.
    ///
    /// # Arguments
    /// - `c1`: The first ciphertext.
    /// - `c2`: The second ciphertext.
    /// - `plain_bits`: The bit-length of the plaintext data.
    ///
    /// # Returns
    ///
    /// A ciphertext decrypting to `1` if `c1` >= `c2`, otherwise `0`.
    pub fn greater_than_equal<M>(&self, c1: &LweCiphertext<C>, c2: &LweCiphertext<C>, plain_bits: u32) -> LweCiphertext<C>
    where
        M: Copy + ReduceNeg<C, Output = C> + ReduceAddAssign<C>,
    {
        let greater_than_enc = self.greater_than::<C>(c2, c1, plain_bits);
        let output = self.homnot(&greater_than_enc);
        output
    }

    /// Produces a ciphertext indicating whether `c1` < `c2`.
    ///
    /// Internally, this is computed as `greater_than(c2, c1)`.
    /// If `c2` is greater than `c1`, the result is `1`; otherwise, `0`.
    ///
    /// # Type Parameters
    /// - `M`: A type parameter for modular arithmetic operations.
    ///
    /// # Arguments
    /// - `c1`: The first ciphertext.
    /// - `c2`: The second ciphertext.
    /// - `plain_bits`: The bit-length of the plaintext data.
    ///
    /// # Returns
    ///
    /// A ciphertext decrypting to `1` if `c1` < `c2`, otherwise `0`.
    pub fn less_than<M>(&self, c1: &LweCiphertext<C>, c2: &LweCiphertext<C>, plain_bits: u32) -> LweCiphertext<C>
    where
        M: Copy + ReduceNeg<C, Output = C> + ReduceAddAssign<C>,
    {
        let output = self.greater_than::<C>(c2, c1, plain_bits);
        output
    }

    /// Produces a ciphertext indicating whether `c1` <= `c2`.
    ///
    /// Internally, this is computed as `greater_than_equal(c2, c1)`.
    /// If `c2` >= `c1`, the result is `1`; otherwise, `0`.
    ///
    /// # Type Parameters
    /// - `M`: A type parameter for modular arithmetic operations.
    ///
    /// # Arguments
    /// - `c1`: The first ciphertext.
    /// - `c2`: The second ciphertext.
    /// - `plain_bits`: The bit-length of the plaintext data.
    ///
    /// # Returns
    ///
    /// A ciphertext decrypting to `1` if `c1` <= `c2`, otherwise `0`.
    pub fn less_than_equal<M>(&self, c1: &LweCiphertext<C>, c2: &LweCiphertext<C>, plain_bits: u32) -> LweCiphertext<C>
    where
        M: Copy + ReduceNeg<C, Output = C> + ReduceAddAssign<C>,
    {
        let output = self.greater_than_equal::<C>(c2, c1, plain_bits);
        output
    }

    /// Produces a ciphertext indicating whether `c1` == `c2`.
    ///
    /// Internally, this is computed by evaluating both `c1 <= c2` and `c1 >= c2`,
    /// then applying a homomorphic AND. If both are true, then `c1 == c2`.
    ///
    /// # Type Parameters
    /// - `M`: A type parameter for modular arithmetic operations.
    ///
    /// # Arguments
    /// - `c1`: The first ciphertext.
    /// - `c2`: The second ciphertext.
    /// - `plain_bits`: The bit-length of the plaintext data.
    ///
    /// # Returns
    ///
    /// A ciphertext decrypting to `1` if `c1` and `c2` represent the same value,
    /// otherwise `0`.
    pub fn equal<M>(&self, c1: &LweCiphertext<C>, c2: &LweCiphertext<C>, plain_bits: u32) -> LweCiphertext<C>
    where
        M: Copy + ReduceNeg<C, Output = C> + ReduceAddAssign<C>,
    {
        // Compute (c1 <= c2) AND (c1 >= c2).
        let cipher_1 = c1.clone();
        let cipher_2 = c2.clone();
        let less_than_cipher = self.less_than_equal::<M>(&cipher_1, &cipher_2, plain_bits);
        let greater_than_cipher = self.greater_than_equal::<M>(&cipher_1, &cipher_2, plain_bits);

        let output = self.homand::<M>(&less_than_cipher, &greater_than_cipher);
        output
    }
}