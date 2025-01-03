use std::sync::Arc;

use algebra::{
    decompose::NonPowOf2ApproxSignedBasis, ntt::NttTable, random::DiscreteGaussian, Field, NttField,
};
use lattice::{utils::PolyDecomposeSpace, NttGadgetRlwe, NttRlwe};
use rand::{CryptoRng, Rng};

use crate::{utils::Pool, NttRlweSecretKey, RlweCiphertext};

/// The Key Switching Key.
#[derive(Clone)]
pub struct RlweKeySwitchingKey<Q: NttField> {
    key: NttGadgetRlwe<Q>,
    ntt_table: Arc<<Q as NttField>::Table>,
    space: Pool<PolyDecomposeSpace<Q>>,
}

impl<Q: NttField> RlweKeySwitchingKey<Q> {
    /// Creates a new [`RlweKeySwitchingKey<Q>`].
    #[inline]
    pub fn new(key: NttGadgetRlwe<Q>, ntt_table: Arc<<Q as NttField>::Table>) -> Self {
        Self {
            key,
            ntt_table,
            space: Pool::new(),
        }
    }

    /// Generates a new `RlweKeySwitchingKey` using the provided input and output RLWE secret keys,
    /// basis, Gaussian distribution, NTT table, and random number generator.
    ///
    /// # Arguments
    ///
    /// * `s_in` - A reference to the input RLWE secret key.
    /// * `s_out` - A reference to the output RLWE secret key.
    /// * `basis` - The basis for the key switching.
    /// * `gaussian` - The Gaussian distribution used for generating random samples.
    /// * `ntt_table` - The NTT table used for Number Theoretic Transform operations.
    /// * `rng` - A mutable reference to a random number generator.
    ///
    /// # Returns
    ///
    /// A new instance of `RlweKeySwitchingKey`.
    pub fn generate<R>(
        s_in: &NttRlweSecretKey<Q>,
        s_out: &NttRlweSecretKey<Q>,
        basis: &NonPowOf2ApproxSignedBasis<<Q as Field>::ValueT>,
        gaussian: DiscreteGaussian<<Q as Field>::ValueT>,
        ntt_table: Arc<<Q as NttField>::Table>,
        rng: &mut R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        // other case will be added later.
        assert_eq!(s_in.coeff_count(), s_out.coeff_count());

        let key = NttGadgetRlwe::generate_random_poly_sample(
            s_out, s_in, basis, gaussian, &ntt_table, rng,
        );

        Self {
            key,
            ntt_table,
            space: Pool::new(),
        }
    }

    /// Performs key switching on the given RLWE ciphertext.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - A reference to the RLWE ciphertext to be key switched.
    ///
    /// # Returns
    ///
    /// A new RLWE ciphertext after key switching.
    pub fn key_switch(&self, ciphertext: &RlweCiphertext<Q>) -> RlweCiphertext<Q> {
        let ntt_table = self.ntt_table.as_ref();
        let coeff_count = ntt_table.dimension();

        let mut decompose_space = match self.space.get() {
            Some(sp) => sp,
            None => PolyDecomposeSpace::new(coeff_count),
        };

        let mut ntt_rlwe = <NttRlwe<Q>>::zero(coeff_count);

        self.key.mul_polynomial_inplace_fast(
            ciphertext.a(),
            ntt_table,
            &mut decompose_space,
            &mut ntt_rlwe,
        );

        self.space.store(decompose_space);

        let mut result = ntt_rlwe.to_rlwe(ntt_table);
        result.a_mut().neg_assign();
        result.b_mut().neg_assign();
        *result.b_mut() += ciphertext.b();

        result
    }
}
