use num_traits::{ConstOne, ConstZero};
use primus_glwe::BlockOccupancy;
use primus_integer::FheUint;
use primus_lattice::{GlweDimension, GlweSize};
use primus_reduce::RingContext;

use crate::{GlweSecretKey, LweSecretKey, PbsOrder, PbsParameters, TfheKeyError};

mod external;

pub use external::ExternalLweSecretKey;

/// The complete secret bundle for GLWE TFHE setup and evaluation-key generation.
/// Ordinary clients borrow only [`Self::external_lwe_secret_key`]; ring clients
/// borrow [`Self::glwe_secret_key`]. Use [`Self::into_parts`] to retain roles separately.
///
/// The GLWE key is kept in signed coefficient form. Fourier and NTT
/// representations are derived temporarily while generating evaluation keys.
#[derive(Clone)]
pub struct ClientKey<T: FheUint> {
    small_lwe_secret_key: LweSecretKey<T>,
    glwe_secret_key: GlweSecretKey<T>,
    pbs_order: PbsOrder,
}

impl<T: FheUint> ClientKey<T> {
    /// Generates both coefficient-domain client secrets without transform tables.
    ///
    /// Distribution and fixed-weight validity is established by parameter construction.
    #[must_use]
    pub fn generate<M, LM, R>(parameters: &PbsParameters<T, M, LM>, rng: &mut R) -> Self
    where
        M: RingContext<T>,
        LM: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let bsk_params = parameters.blind_rotation_params();
        Self::new(
            LweSecretKey::generate(parameters.small_lwe(), rng),
            GlweSecretKey::generate(
                bsk_params.glwe_size(),
                bsk_params.encryption_parameters().secret_key_sampler(),
                rng,
            ),
            parameters.pbs_order(),
        )
    }

    /// Creates a client key from its LWE and coefficient-domain GLWE keys.
    ///
    /// # Correctness
    ///
    /// This only groups the secrets and PBS order. Imported coefficients retain
    /// their owning key types' numerical and distribution contracts. Later
    /// [`Self::check_compatible`] checks do not validate GLWE coefficient
    /// magnitudes or the actual secret pairing with separately generated
    /// server material.
    #[must_use]
    #[inline]
    pub fn new(
        small_lwe_secret_key: LweSecretKey<T>,
        glwe_secret_key: GlweSecretKey<T>,
        pbs_order: PbsOrder,
    ) -> Self {
        Self {
            small_lwe_secret_key,
            glwe_secret_key,
            pbs_order,
        }
    }

    /// Returns the secret key used by external LWE ciphertexts.
    ///
    /// Bootstrap-then-key-switch uses the small-LWE key. Key-switch-then-
    /// bootstrap uses the coefficient expansion of the GLWE key. The returned
    /// role retains the owner metadata and is validated when binding a client.
    #[must_use]
    #[inline]
    pub fn external_lwe_secret_key(&self) -> ExternalLweSecretKey<'_, T> {
        match self.pbs_order {
            PbsOrder::BootstrapKeyswitch => {
                ExternalLweSecretKey::SmallLwe(&self.small_lwe_secret_key)
            }
            PbsOrder::KeyswitchBootstrap => {
                ExternalLweSecretKey::ExtractedGlwe(&self.glwe_secret_key)
            }
        }
    }

    /// Returns the small-LWE secret key used by the bootstrapping key.
    #[must_use]
    #[inline]
    pub fn small_lwe_secret_key(&self) -> &LweSecretKey<T> {
        &self.small_lwe_secret_key
    }

    /// Returns the coefficient-domain GLWE secret key.
    #[must_use]
    #[inline]
    pub fn glwe_secret_key(&self) -> &GlweSecretKey<T> {
        &self.glwe_secret_key
    }

    /// Returns the padded GLWE key used as the target of TFHE GLWE key switching.
    ///
    /// The small LWE coefficients occupy the prefix in their natural order;
    /// the remaining coefficients are zero. Ternary `q-1` residues are decoded
    /// to signed `-1`, including for explicit moduli. `parameters` must already
    /// have passed [`Self::check_compatible`]. Block partitions belong only to
    /// the logical LWE prefix; the public zero tail need not form whole blocks.
    ///
    /// # Panics
    ///
    /// Panics if the small secret is not binary/ternary, or a coefficient lies
    /// outside its declared support under the supplied modulus.
    #[must_use]
    pub fn padded_small_glwe_secret_key<M, LM>(
        &self,
        parameters: &PbsParameters<T, M, LM>,
    ) -> GlweSecretKey<T>
    where
        M: RingContext<T>,
        LM: RingContext<T>,
    {
        let lwe_secret_key = &self.small_lwe_secret_key;
        let lwe_dimension = lwe_secret_key.dimension();
        let poly_length = parameters.blind_rotation_params().poly_length().get();
        let capacity = lwe_dimension
            .checked_next_multiple_of(poly_length)
            .expect("validated TFHE dimensions must fit in usize");

        let mut key = vec![T::SignedInteger::ZERO; capacity];
        let distribution = lwe_secret_key.distr();
        assert!(
            distribution.is_binary() || distribution.is_ternary(),
            "TFHE small LWE secret keys must use a binary or ternary distribution"
        );
        let minus_one = parameters.small_lwe().cipher_modulus().minus_one();
        key[..lwe_dimension]
            .iter_mut()
            .zip(lwe_secret_key.as_ref())
            .for_each(|(output, &coefficient)| {
                *output = if coefficient <= T::ONE {
                    coefficient.cast_to_signed()
                } else {
                    assert!(
                        distribution.is_ternary() && coefficient == minus_one,
                        "small LWE secret coefficient is outside its declared support"
                    );
                    -T::SignedInteger::ONE
                };
            });

        GlweSecretKey::new(
            key,
            GlweSize::new(
                GlweDimension::new(capacity / poly_length),
                parameters.blind_rotation_params().poly_length(),
            ),
            distribution,
        )
    }

    /// Returns the PBS order that determines the external LWE key.
    #[must_use]
    #[inline]
    pub fn pbs_order(&self) -> PbsOrder {
        self.pbs_order
    }

    /// Checks the full setup bundle before evaluation-key generation.
    /// Validates key shapes, distribution labels and the small-LWE coefficient domain.
    /// The owning small-LWE modulus is checked before creating any raw key view.
    ///
    /// Imported small-LWE coefficients must be `0/1`, or also `q-1` for ternary
    /// distributions. Block-binary secrets must satisfy their declared occupancy.
    /// This does not validate fixed weights or the accumulator's
    /// coefficient magnitudes; transform backends retain their range contracts.
    pub fn check_compatible<M, LM>(
        &self,
        parameters: &PbsParameters<T, M, LM>,
    ) -> Result<(), TfheKeyError>
    where
        M: RingContext<T>,
        LM: RingContext<T>,
    {
        if self.pbs_order != parameters.pbs_order() {
            return Err(TfheKeyError::PbsOrderMismatch {
                expected: parameters.pbs_order(),
                actual: self.pbs_order,
            });
        }
        parameters.check_small_lwe_secret_key(&self.small_lwe_secret_key)?;
        parameters.check_accumulator_secret_key(&self.glwe_secret_key)
    }

    /// Returns the two secret keys and the PBS order defining their external role.
    #[must_use]
    #[inline]
    pub fn into_parts(self) -> (LweSecretKey<T>, GlweSecretKey<T>, PbsOrder) {
        (
            self.small_lwe_secret_key,
            self.glwe_secret_key,
            self.pbs_order,
        )
    }
}

impl<T: FheUint, M: RingContext<T>, LM: RingContext<T>> PbsParameters<T, M, LM> {
    /// Checks the small secret at setup or external-client binding, before raw views.
    pub(crate) fn check_small_lwe_secret_key(
        &self,
        key: &LweSecretKey<T>,
    ) -> Result<(), TfheKeyError> {
        if key.dimension() != self.small_lwe().dimension().get() {
            return Err(TfheKeyError::LweDimensionMismatch {
                expected: self.small_lwe().dimension().get(),
                actual: key.dimension(),
            });
        }
        if key.cipher_modulus_minus_one() != self.small_lwe().cipher_modulus_minus_one() {
            return Err(TfheKeyError::LweSecretKeyModulusMismatch);
        }
        if key.distr() != self.small_lwe().secret_key_distr() {
            return Err(TfheKeyError::LweSecretKeyDistributionMismatch);
        }
        if let crate::SecretKeyDistr::BlockBinary {
            block_size,
            occupancy,
        } = key.distr()
        {
            // Parameters established n % block_size == 0. Check coefficients
            // and occupancy in one full scan, without stopping on secret data.
            let mut invalid_coefficient = false;
            let mut invalid_block = false;
            let require_one = occupancy == BlockOccupancy::ExactlyOne;
            for block in key.as_ref().chunks_exact(block_size) {
                let mut occupied = false;
                for &coefficient in block {
                    let selected = coefficient == T::ONE;
                    invalid_coefficient |= coefficient > T::ONE;
                    invalid_block |= occupied & selected;
                    occupied |= selected;
                }
                invalid_block |= require_one & !occupied;
            }
            if invalid_coefficient {
                return Err(TfheKeyError::InvalidLweSecretKeyCoefficient);
            }
            if invalid_block {
                return Err(TfheKeyError::InvalidLweSecretKeyBlock);
            }
            return Ok(());
        }
        let ternary = key.distr().is_ternary();
        let minus_one = self.small_lwe().cipher_modulus().minus_one();
        // Inspect the complete secret instead of stopping at the first bad coefficient.
        let invalid = key.as_ref().iter().fold(false, |invalid, &coefficient| {
            invalid | ((coefficient > T::ONE) & !(ternary & (coefficient == minus_one)))
        });
        if invalid {
            return Err(TfheKeyError::InvalidLweSecretKeyCoefficient);
        }
        Ok(())
    }

    /// Checks only the accumulator secret's shape and distribution label.
    /// This does not inspect the small-LWE secret, prove key identity, or validate
    /// signed coefficient magnitudes required by the selected transform backend.
    pub fn check_accumulator_secret_key(&self, key: &GlweSecretKey<T>) -> Result<(), TfheKeyError> {
        if key.dimension() != self.blind_rotation_params().dimension() {
            return Err(TfheKeyError::GlweDimensionMismatch {
                expected: self.blind_rotation_params().dimension().get(),
                actual: key.dimension().get(),
            });
        }
        if key.poly_length() != self.blind_rotation_params().poly_length() {
            return Err(TfheKeyError::PolynomialLengthMismatch {
                expected: self.blind_rotation_params().poly_length().get(),
                actual: key.poly_length().get(),
            });
        }
        if key.distr() != self.blind_rotation_params().secret_key_distr() {
            return Err(TfheKeyError::GlweSecretKeyDistributionMismatch);
        }
        Ok(())
    }
}
