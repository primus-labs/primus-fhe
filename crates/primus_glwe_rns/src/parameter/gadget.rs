//! CRT GLev/GGSW decomposition basis and reconstruction weights.

use primus_decompose::{
    DecompositionBaseLog, DecompositionLevelCount, big_integer::BigUintApproxSignedBasis,
};
use primus_distr::SignedDiscreteGaussian;
use primus_integer::{BigUint, FheUint};
use primus_lattice::{GlweDimension, RnsGadgetSize};
use primus_reduce::FieldContext;
use primus_rns::{RNSBase, Residues};
use primus_shape::PolyLength;
use rand::distr::Uniform;
use std::sync::Arc;

use super::{CrtGlevParametersError, CrtGlweParameters, core::CrtGlweEncryptionParameters};
use crate::SecretKeyDistr;

/// CRT GLev/GGSW parameters for gadget encryption under the product modulus Q.
///
/// These bind a shared checked layout and prepared sampling state. The gadget
/// owns its ordered RNS base, decomposition basis and cached level weights;
/// plaintext encoding and BFV scaling are not part of this parameter type.
#[derive(Clone)]
pub struct CrtGlevParameters<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    encryption_parameters: Arc<CrtGlweEncryptionParameters<T>>,
    size: RnsGadgetSize,
    base_q: RNSBase<T, M>,
    basis: BigUintApproxSignedBasis<T>,
    /// Reconstruction weights in level-major order, then ordered RNS modulus.
    scalar_residues: Vec<T>,
}

impl<T, M> CrtGlevParameters<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Creates a new [`CrtGlevParameters<T, M>`] from matching GLWE parameters.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_with_glwe_params`] rejects the decomposition parameters.
    #[must_use]
    #[inline]
    pub fn with_glwe_params(
        glwe_params: &CrtGlweParameters<T, M>,
        log_basis: DecompositionBaseLog,
        level_count: Option<DecompositionLevelCount>,
    ) -> Self {
        Self::try_with_glwe_params(glwe_params, log_basis, level_count)
            .unwrap_or_else(|error| panic!("failed to construct CRT GLev parameters: {error}"))
    }

    /// Creates a [`CrtGlevParameters<T, M>`] with checked decomposition and layout.
    /// It uses the ordered RNS base owned by `glwe_params`.
    /// The sampler/base pairing is inherited; the new radix and gadget layout
    /// are still validated before computing level weights.
    ///
    /// The radix `2^log_basis` must be strictly smaller than every RNS modulus,
    /// as required by the fast centered lift used by CRT/DCRT gadget products.
    ///
    /// # Errors
    ///
    /// Returns [`CrtGlevParametersError`] if decomposition construction fails,
    /// a modulus does not satisfy the centered-lift precondition, or a derived
    /// gadget storage length overflows.
    pub fn try_with_glwe_params(
        glwe_params: &CrtGlweParameters<T, M>,
        log_basis: DecompositionBaseLog,
        level_count: Option<DecompositionLevelCount>,
    ) -> Result<Self, CrtGlevParametersError<T>> {
        let basis = BigUintApproxSignedBasis::try_new(
            glwe_params.cipher_modulus(),
            log_basis,
            level_count,
        )?;
        Self::try_from_matching_parts(
            Arc::clone(&glwe_params.encryption_parameters),
            glwe_params.base_q().clone(),
            basis,
        )
    }

    /// Binds prepared layout/samplers, an owned ordered base and decomposition,
    /// without constructing a BFV codec. The base and basis are moved; no converter
    /// or sampling table is rebuilt. Cached weights follow level order, then Q order.
    ///
    /// # Errors
    /// Rejects a base/count/order mismatch, a different product modulus or limb
    /// width, radix >= any q_i, or an overflowing gadget layout. The limb-width
    /// check preserves the exact fixed-width representation used by decomposition.
    pub fn try_from_parts(
        encryption_parameters: Arc<CrtGlweEncryptionParameters<T>>,
        base_q: RNSBase<T, M>,
        basis: BigUintApproxSignedBasis<T>,
    ) -> Result<Self, CrtGlevParametersError<T>> {
        encryption_parameters.validate_base(&base_q)?;
        if basis.modulus() != base_q.moduli_product().0 {
            return Err(CrtGlevParametersError::BasisModulusMismatch);
        }
        Self::try_from_matching_parts(encryption_parameters, base_q, basis)
    }

    /// Sampler order and basis product/limb representation already match this Q.
    /// The new radix still has to fit every q_i for centered gadget lifting;
    /// validate that and the complete layout before allocating level weights.
    fn try_from_matching_parts(
        encryption_parameters: Arc<CrtGlweEncryptionParameters<T>>,
        base_q: RNSBase<T, M>,
        basis: BigUintApproxSignedBasis<T>,
    ) -> Result<Self, CrtGlevParametersError<T>> {
        for (index, modulus) in base_q.moduli().iter().map(|q| q.value()).enumerate() {
            if basis.basis_value() >= modulus {
                return Err(CrtGlevParametersError::BasisNotSmallerThanModulus {
                    basis: basis.basis_value(),
                    modulus,
                    index,
                });
            }
        }
        let size = RnsGadgetSize::try_new(encryption_parameters.size, basis.level_count())?;
        // L*m weights fit because the checked gadget layout contains
        // L*m*(k+1)*N coefficients. Validate that layout before allocating.
        let mut scalar_residues = vec![T::ZERO; basis.level_count().get() * base_q.moduli_count()];
        for (scalar, residues) in basis
            .scalar_iter()
            .zip(scalar_residues.chunks_exact_mut(base_q.moduli_count()))
        {
            base_q.decompose_to(BigUint(scalar), Residues(residues));
        }
        Ok(Self {
            encryption_parameters,
            size,
            base_q,
            basis,
            scalar_residues,
        })
    }

    /// Returns the shared layout and sampling state, without BFV encoding.
    #[must_use]
    #[inline]
    pub fn encryption_parameters(&self) -> &CrtGlweEncryptionParameters<T> {
        &self.encryption_parameters
    }

    /// Returns the dimension of this [`CrtGlevParameters<T, M>`].
    #[must_use]
    #[inline]
    pub fn dimension(&self) -> GlweDimension {
        self.size.rns_glwe_size().dimension()
    }

    /// Returns the poly length of this [`CrtGlevParameters<T, M>`].
    #[must_use]
    #[inline]
    pub fn poly_length(&self) -> PolyLength {
        self.size.rns_glwe_size().poly_length()
    }

    /// Returns a reference to the cipher modulus of this [`CrtGlevParameters<T, M>`].
    #[inline]
    pub fn cipher_modulus(&self) -> BigUint<&[T]> {
        self.base_q.moduli_product()
    }

    /// Returns a reference to the cipher modulus minus one of this [`CrtGlevParameters<T, M>`].
    pub fn cipher_modulus_minus_one(&self) -> BigUint<&[T]> {
        self.encryption_parameters.cipher_modulus_minus_one.view()
    }

    /// Returns the big uint value len of this [`CrtGlevParameters<T, M>`].
    #[inline]
    pub fn big_uint_value_len(&self) -> usize {
        self.base_q.big_uint_value_len()
    }

    /// Returns a reference to the moduli of this [`CrtGlevParameters<T, M>`].
    #[inline]
    pub fn cipher_moduli(&self) -> &[M] {
        self.base_q.moduli()
    }

    /// Returns the moduli count of this [`CrtGlevParameters<T, M>`].
    #[inline]
    pub fn cipher_moduli_count(&self) -> usize {
        self.base_q.moduli_count()
    }

    /// Returns a reference to the cipher moduli value of this [`CrtGlevParameters<T, M>`].
    pub fn cipher_moduli_value(&self) -> &[T] {
        self.base_q.moduli_values()
    }

    /// Returns a reference to the cipher moduli minus one of this [`CrtGlevParameters<T, M>`].
    pub fn cipher_moduli_minus_one(&self) -> &[T] {
        &self.encryption_parameters.cipher_moduli_minus_one
    }

    /// Returns a reference to the cipher moduli uniform distr of this [`CrtGlevParameters<T, M>`].
    pub fn cipher_moduli_uniform_distr(&self) -> &[Uniform<T>] {
        &self.encryption_parameters.cipher_moduli_uniform_distr
    }

    /// Returns the ordered ciphertext RNS basis.
    #[inline]
    pub fn base_q(&self) -> &RNSBase<T, M> {
        &self.base_q
    }

    /// Returns the secret key type of this [`CrtGlevParameters<T, M>`].
    #[inline]
    pub fn secret_key_distr(&self) -> SecretKeyDistr {
        self.encryption_parameters.secret_key_sampler.distr()
    }

    /// Returns a reference to the noise distribution of this [`CrtGlevParameters<T, M>`].
    #[inline]
    pub fn noise_distribution(&self) -> &SignedDiscreteGaussian<T::SignedInteger> {
        &self.encryption_parameters.noise_distribution
    }

    /// Returns the noise standard deviation of this  [`CrtGlevParameters<T, M>`].
    pub fn noise_standard_deviation(&self) -> f64 {
        self.encryption_parameters
            .noise_distribution
            .standard_deviation()
    }

    /// Returns a reference to the basis of this [`CrtGlevParameters<T, M>`].
    #[inline]
    pub fn basis(&self) -> &BigUintApproxSignedBasis<T> {
        &self.basis
    }

    /// Returns cached reconstruction weights modulo each ciphertext modulus.
    ///
    /// Levels follow [`BigUintApproxSignedBasis::decomposer_iter`] from low
    /// to high. Each chunk contains one residue per modulus, in the order of
    /// [`Self::cipher_moduli`]. The weights are computed once at construction.
    #[inline]
    pub fn scalar_residue_iter(
        &self,
    ) -> impl ExactSizeIterator<Item = Residues<&[T]>> + DoubleEndedIterator {
        self.scalar_residues
            .chunks_exact(self.cipher_moduli_count())
            .map(Residues)
    }

    /// Returns the cached RNS gadget layout.
    pub fn size(&self) -> RnsGadgetSize {
        self.size
    }

    /// Returns the coefficient count of one RNS GLev ciphertext.
    pub fn rns_glev_len(&self) -> usize {
        self.size.rns_glev_len()
    }

    /// Returns the coefficient count of one RNS GGSW ciphertext.
    pub fn rns_ggsw_len(&self) -> usize {
        self.size.rns_ggsw_len()
    }

    /// Returns the coefficient count of one RNS polynomial.
    pub fn rns_poly_len(&self) -> usize {
        self.size.rns_glwe_size().rns_poly_len()
    }

    /// Returns the coefficient count of one RNS GLWE ciphertext.
    pub fn rns_glwe_len(&self) -> usize {
        self.size.rns_glwe_size().rns_glwe_len()
    }

    /// Returns the number of decomposition levels.
    #[must_use]
    pub fn level_count(&self) -> DecompositionLevelCount {
        self.basis.level_count()
    }

    /// Returns the limb length of one polynomial in big-integer representation.
    pub fn big_uint_poly_len(&self) -> usize {
        self.poly_length().get() * self.big_uint_value_len()
    }
}

/// CRT GGSW parameters, sharing the GLev decomposition and sampling configuration.
pub type CrtGgswParameters<T, M> = CrtGlevParameters<T, M>;
