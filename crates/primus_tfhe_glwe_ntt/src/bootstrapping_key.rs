//! NTT-domain bootstrapping-key storage and generation.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_glwe::{GlevParameters, NttGlweGadgetEncryptWorkspace, NttGlweSecretKey};
use primus_integer::FheUint;
use primus_lattice::LweDimension;
use primus_lattice::{
    GadgetSize,
    ggsw::{NttGgsw, NttGgswIter},
};
use primus_lwe::LweSecretKey;
use primus_ntt::NttTable;
use primus_reduce::FieldContext;
use primus_tfhe_glwe::SecretKeyDistr;
use zeroize::Zeroizing;

/// An NTT bootstrapping key containing one control per binary input coefficient
/// or an adjacent `(positive, negative)` pair per ternary coefficient. Each pair
/// independently encrypts `[s=1]` and `[s=-1]` under the same accumulator key.
#[derive(Clone)]
pub struct NttGlweBootstrappingKey<T: FheUint> {
    data: Vec<T>,
    input_dimension: LweDimension,
    input_distribution: SecretKeyDistr,
    input_modulus: Option<T>,
    size: GadgetSize,
    cipher_modulus: T,
    basis: ApproxSignedBasis<T>,
}

impl<T: FheUint> NttGlweBootstrappingKey<T> {
    /// Returns the input LWE dimension.
    #[must_use]
    #[inline]
    pub fn input_dimension(&self) -> LweDimension {
        self.input_dimension
    }

    /// Returns the input secret distribution, which fixes the control layout.
    #[must_use]
    #[inline]
    pub fn input_distribution(&self) -> SecretKeyDistr {
        self.input_distribution
    }

    /// Returns the explicit input LWE modulus q, or `None` for the native torus.
    #[must_use]
    #[inline]
    pub fn input_modulus_value(&self) -> Option<T> {
        self.input_modulus
    }

    /// Returns the GGSW/GLWE layout bound to this key.
    #[inline]
    pub fn size(&self) -> GadgetSize {
        self.size
    }

    /// Returns the explicit NTT ciphertext modulus.
    #[inline]
    pub fn cipher_modulus(&self) -> Option<T> {
        Some(self.cipher_modulus)
    }

    /// Returns the decomposition basis bound to this key.
    #[inline]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        &self.basis
    }

    /// Returns the NTT-domain values stored by this key.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.data
    }

    /// Generates an NTT bootstrapping key encrypting the binary coefficients or ternary
    /// selector pairs of the input LWE secret under `output_secret_key`.
    ///
    /// # Correctness
    ///
    /// The output secret key must use the supplied table's NTT roots and evaluation
    /// order; matching modulus metadata does not establish this representation.
    ///
    /// # Panics
    ///
    /// Panics on unsupported distributions or invalid secret coefficients, incompatible key/parameter
    /// layouts or target key modulus, NTT length/modulus or gadget workspace,
    /// key storage overflow, or a rotation domain `2N` not representable by the
    /// input coefficient type.
    pub(crate) fn generate_ntt<M, Table, R>(
        input_secret_key: &LweSecretKey<T>,
        output_secret_key: &NttGlweSecretKey<T>,
        parameters: &GlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        context: &mut NttGlweGadgetEncryptWorkspace<T>,
    ) -> Self
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let input_distribution = input_secret_key.distr();
        assert!(
            input_distribution.is_binary() || input_distribution.is_ternary(),
            "bootstrapping requires a binary or ternary input LWE secret"
        );
        let input_dimension = LweDimension::new(input_secret_key.dimension());
        let control_count = input_dimension
            .get()
            .checked_mul(if input_distribution.is_binary() { 1 } else { 2 })
            .expect("bootstrapping control count overflow");
        // Only ternary key generation needs a temporary selector array. It is
        // erased on drop; the evaluation key retains only encrypted selectors.
        let mut selectors = Zeroizing::new(Vec::new());
        let plaintexts = if input_distribution.is_binary() {
            assert!(
                input_secret_key.as_ref().iter().all(|&x| x <= T::ONE),
                "binary LWE secret coefficient is outside {{0, 1}}"
            );
            input_secret_key.as_ref()
        } else {
            let minus_one = input_secret_key.cipher_modulus_minus_one();
            selectors.resize(control_count, T::ZERO);
            for (&coefficient, pair) in input_secret_key
                .as_ref()
                .iter()
                .zip(selectors.as_chunks_mut::<2>().0.iter_mut())
            {
                assert!(
                    coefficient <= T::ONE || coefficient == minus_one,
                    "ternary LWE secret coefficient is outside {{0, 1, q-1}}"
                );
                pair[0] = if coefficient == T::ONE {
                    T::ONE
                } else {
                    T::ZERO
                };
                pair[1] = if coefficient == minus_one {
                    T::ONE
                } else {
                    T::ZERO
                };
            }
            selectors.as_slice()
        };
        let two_n = 2 * parameters.size().glwe_size().poly_length().get();
        assert!(
            T::try_from(two_n).is_ok(),
            "rotation domain must fit the input coefficient type"
        );
        let ggsw_len = parameters.ggsw_len();
        let total_len = control_count
            .checked_mul(ggsw_len)
            .expect("NTT bootstrapping-key length overflow");
        let mut data = vec![T::ZERO; total_len];
        output_secret_key
            .encrypt_ggsw_constant_batch_to(plaintexts, &mut data, parameters, ntt, rng, context);

        Self {
            data,
            input_dimension,
            input_distribution,
            input_modulus: (input_secret_key.cipher_modulus_minus_one() != T::MAX)
                .then(|| input_secret_key.cipher_modulus_minus_one() + T::ONE),
            size: parameters.size(),
            cipher_modulus: parameters.cipher_modulus().value(),
            basis: parameters.basis().clone(),
        }
    }

    /// Borrows one control per input coordinate, or returns `None` for a ternary key.
    #[must_use]
    pub fn iter_binary_controls(&self) -> Option<NttGgswIter<'_, T>> {
        self.input_distribution
            .is_binary()
            .then(|| NttGgswIter::new(&self.data, self.size.ggsw_len()))
    }

    /// Borrows `(positive, negative)` controls per input coordinate, or returns
    /// `None` for a binary key. The two encryptions in each pair are independent.
    #[must_use]
    #[expect(
        clippy::type_complexity,
        reason = "expose the positive/negative pair without another public type"
    )]
    pub fn iter_ternary_controls(
        &self,
    ) -> Option<impl ExactSizeIterator<Item = (NttGgsw<&[T]>, NttGgsw<&[T]>)>> {
        self.input_distribution.is_ternary().then(|| {
            let len = self.size.ggsw_len();
            self.data.chunks_exact(2 * len).map(move |pair| {
                let (positive, negative) = pair.split_at(len);
                (NttGgsw::new(positive), NttGgsw::new(negative))
            })
        })
    }
}
