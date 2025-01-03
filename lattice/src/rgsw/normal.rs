use algebra::{
    decompose::NonPowOf2ApproxSignedBasis, ntt::NttTable, polynomial::FieldNttPolynomial,
    random::DiscreteGaussian, Field, NttField,
};
use rand::{CryptoRng, Rng};

use crate::{
    utils::{NttRlweSpace, PolyDecomposeSpace},
    GadgetRlwe, Rlwe,
};

use super::NttRgsw;

/// Represents a ciphertext in the Ring-GSW (Ring Learning With Errors) homomorphic encryption scheme.
///
/// The [`Rgsw`] struct holds two components, `m` and `minus_s_m`, each of type [`GadgetRlwe`]. These components are
/// integral to the RGSW encryption scheme, which is a variant of GSW encryption that operates over polynomial
/// rings for efficiency. This scheme is often used in lattice-based cryptography for constructing fully
/// homomorphic encryption systems.
///
/// The [`GadgetRlwe`] structures `m` and `minus_s_m` contain encrypted data that, when used together, allow for the
/// encrypted computation of linear and non-linear operations on ciphertexts without decrypting them.
/// These gadget representations play a crucial role in performing homomorphic operations by controlling noise
/// growth and enabling efficient arithmetic on encrypted data.
///
/// The struct is generic over a type `F` that must implement the [`NttField`] trait, indicating that field
/// operations are compatible with Number Theoretic Transforms. This is essential for the efficient polynomial
/// arithmetic required by the encryption scheme.
pub struct Rgsw<F: NttField> {
    /// The first part of the RGSW ciphertext, which is often used for homomorphic operations
    /// and can represent the encrypted data multiplied by some secret value.
    minus_s_m: GadgetRlwe<F>,
    /// The second part of the RGSW ciphertext, typically representing the encrypted data.
    m: GadgetRlwe<F>,
}

impl<F: NttField> Clone for Rgsw<F> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            minus_s_m: self.minus_s_m.clone(),
            m: self.m.clone(),
        }
    }
}

impl<F: NttField> Rgsw<F> {
    /// Creates a new [`Rgsw<F>`].
    #[inline]
    pub fn new(minus_s_m: GadgetRlwe<F>, m: GadgetRlwe<F>) -> Self {
        Self { minus_s_m, m }
    }

    /// Creates a new [`Rgsw<F>`] with reference.
    #[inline]
    pub fn from_ref(minus_s_m: &GadgetRlwe<F>, m: &GadgetRlwe<F>) -> Self {
        Self {
            minus_s_m: minus_s_m.clone(),
            m: m.clone(),
        }
    }

    /// Creates a [`Rgsw<F>`] with all entries equal to zero.
    #[inline]
    pub fn zero(
        coeff_count: usize,
        basis: NonPowOf2ApproxSignedBasis<<F as Field>::ValueT>,
    ) -> Self {
        Self {
            minus_s_m: GadgetRlwe::zero(coeff_count, basis),
            m: GadgetRlwe::zero(coeff_count, basis),
        }
    }

    /// Set all entries equal to zero.
    #[inline]
    pub fn set_zero(&mut self) {
        self.m.set_zero();
        self.minus_s_m.set_zero();
    }

    /// Returns a reference to the `-s*m` of this [`Rgsw<F>`].
    #[inline]
    pub fn minus_s_m(&self) -> &GadgetRlwe<F> {
        &self.minus_s_m
    }

    /// Returns a mutable reference to the `-s*m` of this [`Rgsw<F>`].
    #[inline]
    pub fn minus_s_m_mut(&mut self) -> &mut GadgetRlwe<F> {
        &mut self.minus_s_m
    }

    /// Returns a reference to the `m` of this [`Rgsw<F>`].
    #[inline]
    pub fn m(&self) -> &GadgetRlwe<F> {
        &self.m
    }

    /// Returns a mutable reference to the `m` of this [`Rgsw<F>`].
    #[inline]
    pub fn m_mut(&mut self) -> &mut GadgetRlwe<F> {
        &mut self.m
    }

    /// Returns the basis of this [`Rgsw<F>`].
    #[inline]
    pub fn basis(&self) -> &NonPowOf2ApproxSignedBasis<<F as Field>::ValueT> {
        self.minus_s_m.basis()
    }

    /// Converts self into [NttRgsw<F>].
    #[inline]
    pub fn to_ntt_rgsw(self, ntt_table: &<F as NttField>::Table) -> NttRgsw<F> {
        NttRgsw::new(
            self.minus_s_m.to_ntt_gadget_rlwe(ntt_table),
            self.m.to_ntt_gadget_rlwe(ntt_table),
        )
    }

    /// Performs addition operation:`self + rhs`,
    /// and puts the result to the `destination`.
    #[inline]
    pub fn add_inplace(&self, rhs: &Self, destination: &mut Self) {
        self.m.add_inplace(rhs.m(), destination.m_mut());
        self.minus_s_m
            .add_inplace(rhs.minus_s_m(), destination.minus_s_m_mut());
    }

    /// Performs subtraction operation:`self - rhs`,
    /// and put the result to the `destination`.
    #[inline]
    pub fn sub_inplace(&self, rhs: &Self, destination: &mut Self) {
        self.m.sub_inplace(rhs.m(), destination.m_mut());
        self.minus_s_m
            .sub_inplace(rhs.minus_s_m(), destination.minus_s_m_mut());
    }

    /// Performs a multiplication on the `self` [`Rgsw<F>`] with another `small_ntt_rgsw` [`NttRgsw<F>`],
    /// return a [`Rgsw<F>`].
    pub fn mul_small_ntt_rgsw(
        &self,
        ntt_rgsw: &NttRgsw<F>,
        ntt_table: &<F as NttField>::Table,
    ) -> Self {
        let basis = self.basis();
        let dimension = ntt_table.dimension();

        let decompose_space = &mut PolyDecomposeSpace::new(dimension);
        let median = &mut NttRlweSpace::new(dimension);

        let c0_data: Vec<_> = self
            .minus_s_m
            .iter()
            .map(|rlwe| {
                let mut detination = Rlwe::zero(dimension);
                rlwe.mul_ntt_rgsw_inplace(
                    ntt_rgsw,
                    ntt_table,
                    decompose_space,
                    median,
                    &mut detination,
                );
                detination
            })
            .collect();

        let minus_s_m = GadgetRlwe::new(c0_data, *basis);

        let c1_data: Vec<_> = self
            .m
            .iter()
            .map(|rlwe| {
                let mut detination = Rlwe::zero(dimension);
                rlwe.mul_ntt_rgsw_inplace(
                    ntt_rgsw,
                    ntt_table,
                    decompose_space,
                    median,
                    &mut detination,
                );
                detination
            })
            .collect();

        let m = GadgetRlwe::new(c1_data, *basis);

        Self::new(minus_s_m, m)
    }

    /// Generate a [`Rgsw<F>`] sample which encrypts `0`.
    pub fn generate_random_zero_sample<R>(
        secret_key: &FieldNttPolynomial<F>,
        basis: &NonPowOf2ApproxSignedBasis<<F as Field>::ValueT>,
        gaussian: DiscreteGaussian<<F as Field>::ValueT>,
        ntt_table: &<F as NttField>::Table,
        rng: &mut R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        Self {
            minus_s_m: <GadgetRlwe<F>>::generate_random_zero_sample(
                secret_key, basis, gaussian, ntt_table, rng,
            ),
            m: <GadgetRlwe<F>>::generate_random_zero_sample(
                secret_key, basis, gaussian, ntt_table, rng,
            ),
        }
    }

    /// Generate a [`Rgsw<F>`] sample which encrypts `1`.
    pub fn generate_random_one_sample<R>(
        secret_key: &FieldNttPolynomial<F>,
        basis: &NonPowOf2ApproxSignedBasis<<F as Field>::ValueT>,
        gaussian: DiscreteGaussian<<F as Field>::ValueT>,
        ntt_table: &<F as NttField>::Table,
        rng: &mut R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        Self {
            minus_s_m: <GadgetRlwe<F>>::generate_random_neg_secret_sample(
                secret_key, basis, gaussian, ntt_table, rng,
            ),
            m: <GadgetRlwe<F>>::generate_random_one_sample(
                secret_key, basis, gaussian, ntt_table, rng,
            ),
        }
    }
}
