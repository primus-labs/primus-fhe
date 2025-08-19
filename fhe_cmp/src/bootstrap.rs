use crate::{parameter::Steps, CmpFheParameters, SecretKeyPack};
use algebra::{
    integer::{AsFrom, UnsignedInteger},
    polynomial::FieldPolynomial,
    reduce::{ModulusValue, ReduceAddAssign, ReduceNeg, RingReduce},
    Field, NttField,
};
use fhe_core::{
    lwe_modulus_switch, lwe_modulus_switch_assign, lwe_modulus_switch_inplace, BlindRotationKey,
    LweCiphertext, LweKeySwitchingKeyRlweMode, LweSecretKey, LweSecretKeyType,
    NonPowOf2LweKeySwitchingKey, PowOf2LweKeySwitchingKey, RingSecretKeyType,
};
use rand::{CryptoRng, Rng};
use std::f64::consts::LOG2_E;
use std::sync::Arc;

/// A enum type for different key switching purposes.
#[derive(Clone)]
pub enum KeySwitchingKey<C: UnsignedInteger, Q: NttField> {
    /// The key switching is based on rlwe multiply with gadget rlwe.
    PowOf2DimensionLwe(LweKeySwitchingKeyRlweMode<Q>),
    /// The key switching is based on LWE constant multiplication.
    PowOf2ModulusLwe(PowOf2LweKeySwitchingKey<C>),
    /// The key switching is based on non power of 2 modulus LWE.
    NonPowOf2ModulusLwe(NonPowOf2LweKeySwitchingKey<<Q as Field>::ValueT>),
    /// No key switching.
    None,
}

impl<C: UnsignedInteger, Q: NttField> KeySwitchingKey<C, Q> {
    /// Returns an `Option` containing a reference to the
    /// `LweKeySwitchingKeyRlweMode<Q>` if the key is in `PowOf2DimensionLwe` mode, otherwise `None`.
    /// Returns an `Option` containing a reference to the
    /// `NonPowOf2LweKeySwitchingKey<<Q as Field>::ValueT>` if the key is in `NonPowOf2ModulusLwe` mode,
    /// otherwise `None`.
    #[inline]
    pub fn as_non_pow_of_2_modulus_lwe(
        &self,
    ) -> Option<&NonPowOf2LweKeySwitchingKey<<Q as Field>::ValueT>> {
        if let Self::NonPowOf2ModulusLwe(v) = self {
            Some(v)
        } else {
            None
        }
    }
}

/// The evaluator of the homomorphic encryption scheme.
#[derive(Clone)]
pub struct EvaluationKey<C: UnsignedInteger, LweModulus: RingReduce<C>, Q: NttField> {
    /// Blind rotation key.
    blind_rotation_key: BlindRotationKey<Q>,
    /// Key switching key.
    key_switching_key: KeySwitchingKey<C, Q>,
    /// The parameters of the fully homomorphic encryption scheme.
    parameters: CmpFheParameters<C, LweModulus, Q>,
}

impl<C: UnsignedInteger, LweModulus: RingReduce<C>, Q: NttField> EvaluationKey<C, LweModulus, Q> {
    /// Returns a reference to the parameters of this [`EvaluationKey<C, LweModulus, Q>`].
    #[inline]
    pub fn parameters(&self) -> &CmpFheParameters<C, LweModulus, Q> {
        &self.parameters
    }

    /// Creates a new [`EvaluationKey`] from the given [`SecretKeyPack`].
    #[inline]
    pub fn new<R>(secret_key_pack: &SecretKeyPack<C, LweModulus, Q>, rng: &mut R) -> Self
    where
        R: Rng + CryptoRng,
    {
        let parameters = secret_key_pack.parameters();

        let blind_rotation_key = BlindRotationKey::generate(
            secret_key_pack.lwe_secret_key(),
            secret_key_pack.ntt_rlwe_secret_key(),
            parameters.blind_rotation_basis(),
            &parameters.ring_noise_distribution(),
            Arc::clone(secret_key_pack.ntt_table()),
            rng,
        );

        let s_in = secret_key_pack.rlwe_secret_key();
        let s_out = secret_key_pack.lwe_secret_key();
        let key_switching_key = match parameters.steps() {
            Steps::BrMsKs => {
                let lwe_cipher_modulus_minus_one = parameters.lwe_cipher_modulus_minus_one();
                let s_in = LweSecretKey::from_rlwe_secret_key(s_in, lwe_cipher_modulus_minus_one);

                let ksk = PowOf2LweKeySwitchingKey::generate(
                    &s_in,
                    s_out,
                    parameters.key_switching_params(),
                    parameters.lwe_cipher_modulus(),
                    rng,
                );
                KeySwitchingKey::PowOf2ModulusLwe(ksk)
            }
            Steps::BrKsRlevMs => {
                let ksk: LweKeySwitchingKeyRlweMode<Q> = LweKeySwitchingKeyRlweMode::generate(
                    s_in,
                    s_out,
                    parameters.key_switching_params(),
                    Arc::clone(secret_key_pack.ntt_table()),
                    rng,
                );
                KeySwitchingKey::PowOf2DimensionLwe(ksk)
            }
            Steps::BrKsLevMs => {
                let distr = match s_in.distr() {
                    RingSecretKeyType::Binary => LweSecretKeyType::Binary,
                    RingSecretKeyType::Ternary => LweSecretKeyType::Ternary,
                    RingSecretKeyType::Gaussian => panic!("Not support"),
                };
                let s_in = LweSecretKey::new(s_in.as_slice().to_vec(), distr);

                let ksk: NonPowOf2LweKeySwitchingKey<<Q as Field>::ValueT> =
                    NonPowOf2LweKeySwitchingKey::generate(
                        &s_in,
                        s_out,
                        parameters.key_switching_params(),
                        Q::MODULUS,
                        rng,
                    );
                KeySwitchingKey::NonPowOf2ModulusLwe(ksk)
            }
            Steps::BrMs => KeySwitchingKey::None,
        };

        Self {
            blind_rotation_key,
            key_switching_key,
            parameters: *parameters,
        }
    }

    /// Complete the bootstrapping operation with LWE Ciphertext *`c`* and lookup table `lut`.
    pub fn bootstrap(&self, mut c: LweCiphertext<C>, lut: FieldPolynomial<Q>) -> LweCiphertext<C> {
        let parameters = self.parameters();
        let twice_ring_dimension_value =
            C::try_from(parameters.ring_dimension() << 1).ok().unwrap();

        // modulus switch q -> 2N
        lwe_modulus_switch_assign(
            &mut c,
            parameters.lwe_cipher_modulus_value(),
            twice_ring_dimension_value,
        );
        // blind rotation
        let acc = self.blind_rotation_key.blind_rotate(lut, &c);
        // key switch and modulus switch (N, Q) -> (n, q)
        match parameters.steps() {
            Steps::BrMsKs => {
                let acc = acc.extract_lwe_locally();
                let cipher = lwe_modulus_switch(
                    &acc,
                    parameters.ring_modulus(),
                    parameters.lwe_cipher_modulus_value(),
                );

                let ksk = match self.key_switching_key {
                    KeySwitchingKey::PowOf2ModulusLwe(ref ksk) => ksk,
                    _ => panic!("Unable to get the corresponding key switching key!"),
                };

                c = ksk.key_switch(&cipher, parameters.lwe_cipher_modulus());
            }
            Steps::BrKsRlevMs => {
                let ksk = match self.key_switching_key {
                    KeySwitchingKey::PowOf2DimensionLwe(ref ksk) => ksk,
                    _ => panic!("Unable to get the corresponding key switching key!"),
                };

                let key_switched = ksk.key_switch_for_rlwe(acc);

                lwe_modulus_switch_inplace(
                    key_switched,
                    Q::MODULUS_VALUE,
                    parameters.lwe_cipher_modulus_value(),
                    &mut c,
                );
            }
            Steps::BrKsLevMs => {
                let acc = acc.extract_lwe_locally();
                let ksk = self
                    .key_switching_key
                    .as_non_pow_of_2_modulus_lwe()
                    .unwrap();
                let temp = ksk.key_switch(&acc, Q::MODULUS);

                c = lwe_modulus_switch(
                    &temp,
                    parameters.ring_modulus(),
                    parameters.lwe_cipher_modulus_value(),
                );
            }
            Steps::BrMs => {
                let lwe = acc.extract_lwe_locally();

                lwe_modulus_switch_inplace(
                    lwe,
                    Q::MODULUS_VALUE,
                    parameters.lwe_cipher_modulus_value(),
                    &mut c,
                );
            }
        }

        c
    }
    #[inline]
    /// Initializes a lookup table (LUT) for extracting the most significant bit (MSB).
    ///
    /// This function constructs a polynomial whose coefficients are determined by
    /// a specific bias, which is computed based on the modulus of the `Q` field.
    /// Each coefficient in the resulting polynomial is set to `(Q::MODULUS_VALUE - (Q::MODULUS_VALUE >> 2))`.
    ///
    /// # Returns
    /// A `FieldPolynomial<Q>` of degree `ring_dim`, with every coefficient
    /// set to the computed bias value, enabling MSB extraction in a subsequent step.
    pub fn lut_init_msb(&self) -> FieldPolynomial<Q> {
        // Obtain the polynomial ring dimension from the parameters.
        let ring_dim = self.parameters().ring_dimension();

        // Compute constants used for setting the polynomial's coefficients.
        let mu = Q::MODULUS_VALUE >> 2u32;
        let div_mu = Q::MODULUS_VALUE - mu;

        // Initialize a zero polynomial of the correct degree.
        let mut poly = FieldPolynomial::<Q>::zero(ring_dim);

        // Assign the computed value to each coefficient.
        for coeff in poly.iter_mut() {
            *coeff = div_mu;
        }
        poly
    }

    /// Performs a functional bootstrapping step to isolate the MSB of a ciphertext.
    ///
    /// This method uses a pre-initialized LUT (Lookup Table) to transform the ciphertext
    /// in a way that extracts its most significant bit. Internally, it performs
    /// the following steps:
    ///
    /// 1. Offsets the input ciphertext by adding a small bias.
    /// 2. Bootstraps the ciphertext with the LUT (via `self.bootstrap`).
    /// 3. Adjusts the bootstrapped ciphertext again to center the result on the MSB.
    ///
    /// # Type Parameters
    /// * `M` - A type parameter defining operations for modular negation and addition.
    ///
    /// # Arguments
    /// * `c` - A reference to the LWE ciphertext whose MSB is to be extracted.
    ///
    /// # Returns
    /// A new `LweCiphertext<C>` that, when decrypted, corresponds to the MSB (0 or 1) of the original plaintext.
    pub fn msb_gate<M>(&self, c: &LweCiphertext<C>) -> LweCiphertext<C>
    where
        M: Copy + ReduceNeg<C, Output = C> + ReduceAddAssign<C>,
    {
        let parameters = self.parameters();
        let cipher_modulus = parameters.lwe_cipher_modulus();

        // Build the LUT polynomial for MSB extraction.
        let test_vector = self.lut_init_msb();

        // Retrieve the modulus as a raw integer value for bias adjustments.
        let cipher_modulus_value = match parameters.lwe_cipher_modulus_value() {
            ModulusValue::Native => {
                // In some implementations, this could raise an error or handle differently.
                C::default()
            }
            ModulusValue::PowerOf2(v) | ModulusValue::Prime(v) | ModulusValue::Others(v) => v,
        };
        let cipher_modulus_value: u64 = cipher_modulus_value.as_into();

        // Define offsets and biases.
        let offset = cipher_modulus_value >> 6u32;
        let mu = cipher_modulus_value >> 2u64;

        // Clone and offset the input ciphertext to prepare for bootstrapping.
        let mut cipher = c.clone();
        cipher_modulus.reduce_add_assign(cipher.b_mut(), C::as_from(offset));

        // Perform the actual bootstrapping with the LUT.
        let mut acc = self.bootstrap(cipher, test_vector);

        // Final adjustment to center the result on the MSB.
        cipher_modulus.reduce_add_assign(acc.b_mut(), C::as_from(mu));

        acc
    }

    /// Generates a polynomial lookup table (LUT) for the IDE (Index-based Digit Extraction) operation,
    /// targeting the MSB (or other bits) of a ciphertext based on its scale and plaintext bit sizes.
    ///
    /// # Arguments
    /// * `plain_bits` - The number of bits in the original plaintext representation.
    /// * `scale_bits` - An additional scaling factor in bits, used to shift the polynomial values.
    ///
    /// # Returns
    /// A `FieldPolynomial<Q>` of ring dimension `self.parameters().ring_dimension()`, where each
    /// coefficient is set to a value derived from the LUT logic. Specifically, each coefficient is
    /// computed by shifting its index by `padding_bits` and multiplying by `(Q::MODULUS_VALUE >> scale_bits)`.
    #[inline]
    pub fn lut_init_ide(&self, plain_bits: u32, scale_bits: u32) -> FieldPolynomial<Q> {
        // Calculate the number of padding bits based on the LWE dimension and plain_bits.
        let padding_bits: u32 =
            (((self.parameters().lwe_dimension() as f64) * LOG2_E).log2() as u32) - plain_bits;

        // Create a zero polynomial with degree equal to the ring dimension.
        let mut poly = FieldPolynomial::<Q>::zero(self.parameters().ring_dimension());

        // Compute each coefficient based on the scaled index.
        for (index, coeff) in poly.iter_mut().enumerate() {
            let index = index as u32;
            let padding_index = <Q as Field>::ValueT::as_from(index >> padding_bits);
            let value = (Q::MODULUS_VALUE >> scale_bits) * padding_index;

            *coeff = <Q as Field>::ValueT::as_from(value);
        }

        poly
    }

    /// Performs a specialized MSB gate operation using an IDE (Index-based Digit Extraction) table
    /// to transform the ciphertext and extract high-order bits.
    ///
    /// # Type Parameters
    /// * `M` - A trait bound specifying modular arithmetic operations for negation and addition.
    ///
    /// # Arguments
    /// * `c` - The LWE ciphertext on which the gate operation is performed.
    /// * `scale_bits` - A scaling parameter that influences how the LUT is constructed.
    ///
    /// # Returns
    /// An LWE ciphertext whose high-order bits (e.g., MSB) are extracted via a bootstrapping process
    /// with the generated LUT.
    pub fn ide_msb_gate<M>(&self, c: &LweCiphertext<C>, scale_bits: u32) -> LweCiphertext<C>
    where
        M: Copy + ReduceNeg<C, Output = C> + ReduceAddAssign<C>,
    {
        let parameters = self.parameters();
        let cipher_modulus = parameters.lwe_cipher_modulus();
        let cipher_modulus_value = match parameters.lwe_cipher_modulus_value() {
            ModulusValue::Native => {
                // Could raise an error here; returning default in this example.
                C::default()
            }
            ModulusValue::PowerOf2(v) | ModulusValue::Prime(v) | ModulusValue::Others(v) => v,
        };

        // Clone the ciphertext and offset it by shifting to set up the proper interval for bootstrapping.
        let mut cipher = c.clone();
        let shift: u64 = cipher_modulus_value.as_into();
        let shift = shift >> 6u32;
        cipher_modulus.reduce_add_assign(cipher.b_mut(), C::as_from(shift));

        // Generate the LUT polynomial for IDE-based MSB extraction.
        // For demonstration, `plain_bits` is set to 4.
        let plain_bits = 4u32;
        let test_vector = self.lut_init_ide(plain_bits, scale_bits);

        // Perform the bootstrapping operation with the LUT.
        self.bootstrap(cipher, test_vector)
    }

    /// Builds a lookup table (LUT) polynomial for converting an LWE ciphertext
    /// from its arithmetic domain into a form suitable for logical or MSB extractions.
    ///
    /// # Returns
    /// A `FieldPolynomial<Q>` of ring dimension `self.parameters().ring_dimension()`, where each
    /// coefficient is set to `(Q::MODULUS_VALUE - (Q::MODULUS_VALUE >> 3))`.
    #[inline]
    pub fn lut_ari_to_log(&self) -> FieldPolynomial<Q> {
        let ring_dim = self.parameters().ring_dimension();
        let mu = Q::MODULUS_VALUE >> 3u32;
        let div_mu = Q::MODULUS_VALUE - mu;
        let mut poly = FieldPolynomial::<Q>::zero(ring_dim);

        // Assign the computed value to every coefficient.
        for coeff in poly.iter_mut() {
            *coeff = div_mu;
        }
        poly
    }

    /// Transforms an arithmetic-domain ciphertext into a log-friendly representation
    /// by applying a functional bootstrapping step with a prepared LUT.
    ///
    /// # Type Parameters
    /// * `M` - A trait bound specifying modular arithmetic operations for negation and addition.
    ///
    /// # Arguments
    /// * `c` - The LWE ciphertext to transform.
    ///
    /// # Returns
    /// A new `LweCiphertext<C>` whose representation is more suitable for logical gate operations.
    pub fn ari_to_log<M>(&self, c: &LweCiphertext<C>) -> LweCiphertext<C>
    where
        M: Copy + ReduceNeg<C, Output = C> + ReduceAddAssign<C>,
    {
        let parameters = self.parameters();
        let cipher_modulus = parameters.lwe_cipher_modulus();

        // Generate the LUT polynomial used for the transformation.
        let test_vector = self.lut_ari_to_log();

        let cipher_modulus_value = match parameters.lwe_cipher_modulus_value() {
            ModulusValue::Native => {
                // Could raise an error here; returning default in this example.
                C::default()
            }
            ModulusValue::PowerOf2(v) | ModulusValue::Prime(v) | ModulusValue::Others(v) => v,
        };

        // Subtract a small offset to align the ciphertext correctly before bootstrapping.
        let mut cipher = c.clone();
        let cipher_modulus_value: u64 = cipher_modulus_value.as_into();
        let offset = cipher_modulus_value >> 3u32;
        cipher_modulus.reduce_sub_assign(cipher.b_mut(), C::as_from(offset));

        // Execute the functional bootstrapping with the generated LUT.
        self.bootstrap(cipher, test_vector)
    }
}
