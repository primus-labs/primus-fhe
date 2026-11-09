//! BFV coefficient scaling and decoding over an RNS ciphertext basis.

mod decode;
mod encode;
mod error;

pub use error::BfvRnsCodecError;

use primus_factor::{FactorMul, ShoupFactor};
use primus_integer::{BigUint, DivRemScalar, FheUint, multiply_many_values};
use primus_reduce::FieldContext;
use primus_rns::{BaseConverter, RNSBase, ResidueFactors};

/// BFV-style RNS coefficient codec.
///
/// Encodes `m ∈ Z_t` as canonical RNS residues of `lift(m) * delta mod Q`,
/// where `delta = floor(Q/t)`. Decoding uses fast base conversion to `{t, gamma}`
/// and an auxiliary-modulus correction to recover canonical residues modulo `t`.
/// CRT buffers use coefficient-domain, modulus-major layout in [`Self::base_q`] order.
/// The codec and its converter share the base's immutable tables and numeric
/// modulus cache. Cloning shares those bases but copies codec-specific factors
/// and the conversion matrix.
#[derive(Clone)]
pub struct BfvRnsCodec<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    // Plaintext / ciphertext bases
    t: T,
    base_q: RNSBase<T, M>,

    // For encoding: Δ = floor(Q / t) as BigUint, pre-decomposed into Shoup factors mod each q_i
    delta: BigUint<Vec<T>>,
    delta_factor_mod_q: ResidueFactors<Vec<ShoupFactor<T>>>,

    // For decoding: auxiliary-modulus correction, producing m mod t.
    gamma: T,
    t_modulus: M,
    t_gamma_factor_mod_q: ResidueFactors<Vec<ShoupFactor<T>>>, // [(t·γ) mod q_i]
    // The t factor includes the final division by γ; the γ factor recovers
    // the centered correction before that division.
    decode_factor_mod_t_gamma: [ShoupFactor<T>; 2], // {−(Qγ)^−1 mod t, −Q^−1 mod γ}
    inv_gamma_mod_t: ShoupFactor<T>,                // γ^−1 mod t
    converter_q_to_t_gamma: BaseConverter<T, M>,
}

impl<T, M> BfvRnsCodec<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Creates a new [`BfvRnsCodec<T, M>`].
    ///
    /// Establishes conservative noiseless-recovery bounds:
    /// `Q > 4*(Q % t)*(t-1)` and `gamma > 4*k` for `k` ciphertext moduli.
    /// These are sufficient bounds, not the full set of usable BFV parameters.
    /// The supplied [`RNSBase`] already guarantees a nonempty, pairwise-coprime basis.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_new`] rejects the moduli or recovery bounds.
    #[must_use]
    pub fn new(t_modulus: M, base_q: RNSBase<T, M>, gamma_modulus: M) -> Self {
        Self::try_new(t_modulus, base_q, gamma_modulus)
            .unwrap_or_else(|error| panic!("failed to construct BFV RNS codec: {error}"))
    }

    /// Creates a [`BfvRnsCodec<T, M>`] with checked modulus and recovery conditions.
    ///
    /// The supplied [`RNSBase`] owns the nonempty, pairwise-coprime ciphertext
    /// basis. This constructor checks `t >= 2`, `t < gamma <= T::MAX/2`,
    /// `t < q_i <= T::MAX/2`, and coprimality of `t`, `gamma` and each `q_i`.
    /// It also checks the sufficient recovery bounds documented by [`Self::new`].
    ///
    /// # Correctness
    ///
    /// Modular arithmetic inherits the supplied contexts' numerical contracts.
    /// Multiple ciphertext moduli also require the destination contexts to meet
    /// [`BaseConverter::fast_convert`]'s dot-product input requirements.
    ///
    /// # Errors
    ///
    /// Returns [`BfvRnsCodecError`] if a modulus or recovery condition is invalid.
    pub fn try_new(
        t_modulus: M,
        base_q: RNSBase<T, M>,
        gamma_modulus: M,
    ) -> Result<Self, BfvRnsCodecError<T>> {
        let t = t_modulus.value();
        let gamma = gamma_modulus.value();

        Self::validate_moduli(t, base_q.moduli_values(), gamma)?;

        let cipher_modulus = base_q.moduli_product();

        let mut delta = BigUint(vec![T::ZERO; cipher_modulus.len()]);

        let rem = DivRemScalar::div_rem_scalar(cipher_modulus.digits(), t, delta.digits_mut());
        // Bound the unsigned encoding drift by 1/4 of a decoding cell.
        // Combined with k/gamma < 1/4 this guarantees noiseless recovery.
        let mut drift_bound = multiply_many_values(&[(T::TWO + T::TWO), rem, t - T::ONE]);
        let fits = drift_bound
            .digits()
            .get(cipher_modulus.len()..)
            .is_none_or(|high| high.iter().all(|&x| x == T::ZERO));
        drift_bound.0.resize(cipher_modulus.len(), T::ZERO);
        if !fits || !cipher_modulus.cmp(&drift_bound).is_gt() {
            return Err(BfvRnsCodecError::InsufficientScaleRecovery);
        }

        let delta_factor_mod_q = base_q.decompose_factors(delta.view());

        let t_gamma = [t_modulus, gamma_modulus];
        let base_t_gamma = RNSBase::new(&t_gamma).unwrap();
        let q_mod_t_gamma = base_t_gamma.decompose(cipher_modulus.view());
        let minus_inv_q_mod_t_gamma: [T; 2] = core::array::from_fn(|i| {
            t_gamma[i].reduce_neg(t_gamma[i].reduce_inv(q_mod_t_gamma.as_ref()[i]))
        });
        let inv_gamma_mod_t = ShoupFactor::new(t_modulus.reduce_inv(t_modulus.reduce(gamma)), t);
        let decode_factor_mod_t_gamma = [
            ShoupFactor::new(
                inv_gamma_mod_t.factor_mul_modulo(minus_inv_q_mod_t_gamma[0], t),
                t,
            ),
            ShoupFactor::new(minus_inv_q_mod_t_gamma[1], gamma),
        ];
        let t_gamma_factor_mod_q = base_q.decompose_factors(base_t_gamma.moduli_product());

        let converter_q_to_t_gamma = BaseConverter::from_owned_bases(base_q.clone(), base_t_gamma);

        Ok(Self {
            t,
            base_q,
            delta,
            delta_factor_mod_q,
            gamma,
            t_modulus,
            t_gamma_factor_mod_q,
            decode_factor_mod_t_gamma,
            inv_gamma_mod_t,
            converter_q_to_t_gamma,
        })
    }

    /// Validates the inverse and Shoup domains before preparing scaling factors.
    /// The caller passes the nonempty modulus list of an existing RNSBase.
    fn validate_moduli(
        plain_modulus_value: T,
        cipher_moduli_value: &[T],
        gamma: T,
    ) -> Result<(), BfvRnsCodecError<T>> {
        let limbs = T::try_from(cipher_moduli_value.len())
            .ok()
            .and_then(|k| k.checked_mul(T::TWO + T::TWO))
            .ok_or(BfvRnsCodecError::RnsModulusCountTooLarge {
                count: cipher_moduli_value.len(),
            })?;
        if plain_modulus_value < T::TWO {
            return Err(BfvRnsCodecError::InvalidPlaintextModulus {
                modulus: plain_modulus_value,
            });
        }
        let lower_bound = limbs.max(plain_modulus_value);
        if gamma <= lower_bound {
            return Err(BfvRnsCodecError::AuxiliaryModulusTooSmall { gamma, lower_bound });
        }
        let maximum = T::MAX / T::TWO;
        if gamma > maximum {
            return Err(BfvRnsCodecError::ModulusTooLarge {
                modulus: gamma,
                maximum,
            });
        }
        if !plain_modulus_value.is_coprime(gamma) {
            return Err(BfvRnsCodecError::NonCoprimeModuli {
                lhs: plain_modulus_value,
                rhs: gamma,
            });
        }

        for (index, &qi) in cipher_moduli_value.iter().enumerate() {
            if qi > maximum {
                return Err(BfvRnsCodecError::ModulusTooLarge {
                    modulus: qi,
                    maximum,
                });
            }
            if qi <= plain_modulus_value {
                return Err(BfvRnsCodecError::CiphertextModulusTooSmall {
                    modulus: qi,
                    plain_modulus: plain_modulus_value,
                    index,
                });
            }
            for rhs in [plain_modulus_value, gamma] {
                if !qi.is_coprime(rhs) {
                    return Err(BfvRnsCodecError::NonCoprimeModuli { lhs: qi, rhs });
                }
            }
        }
        Ok(())
    }

    /// Returns the plaintext modulus `t`.
    #[must_use]
    pub fn t(&self) -> T {
        self.t
    }

    /// Returns the ordered ciphertext RNS basis whose product is `Q`.
    #[must_use]
    pub fn base_q(&self) -> &RNSBase<T, M> {
        &self.base_q
    }

    /// Returns the number of ciphertext moduli.
    #[must_use]
    pub fn moduli_count(&self) -> usize {
        self.base_q.moduli_count()
    }

    /// Returns the ordered numeric values of the ciphertext moduli.
    #[must_use]
    pub fn moduli_values(&self) -> &[T] {
        self.base_q.moduli_values()
    }

    /// Returns the Shoup factors for `floor(Q/t) mod q_i` in [`Self::base_q`] order.
    #[must_use]
    pub fn delta_factor_mod_q(&self) -> ResidueFactors<&[ShoupFactor<T>]> {
        self.delta_factor_mod_q.view()
    }

    /// Returns `floor(Q/t)` as a borrowed integer with little-endian limbs.
    #[must_use]
    pub fn delta(&self) -> BigUint<&[T]> {
        self.delta.view()
    }

    /// Shared RNS shape for coefficient buffers and decoding workspace.
    ///
    /// # Panics
    ///
    /// Panics if `poly_length * moduli_count()` overflows `usize`.
    fn rns_poly_len(&self, poly_length: usize) -> usize {
        self.moduli_count()
            .checked_mul(poly_length)
            .expect("RNS polynomial length overflow")
    }
}
