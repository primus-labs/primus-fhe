//! Bounded signed-secret lifting into each ordered NTT modulus.

use primus_integer::FheUint;
use primus_lattice::RnsGlweSize;
use primus_ntt::{DcrtTable, NttTable};
use primus_poly::DcrtPolynomialIterMut;

use super::DcrtGlweSecretKey;
use crate::GlweSecretKey;
use crate::secret_key::encode_secret_polynomial_to;

impl<T: FheUint> DcrtGlweSecretKey<T> {
    /// Creates a modulus-specific DCRT representation of a canonical signed
    /// [`GlweSecretKey<T>`].
    /// Partially converted key storage is erased if encoding or transformation
    /// unwinds; the source secret remains unchanged.
    ///
    /// # Correctness
    ///
    /// Each signed secret coefficient's magnitude must be less than every
    /// modulus in `table`. The table's NTT representation requirements apply;
    /// see [`NttTable::new`].
    ///
    /// # Panics
    ///
    /// Panics if the secret and table polynomial lengths differ, the table has
    /// no moduli, or the derived RNS storage length overflows.
    #[inline]
    #[must_use]
    pub fn from_coeff_secret_key<Table>(
        secret_key: &GlweSecretKey<T>,
        table: &DcrtTable<Table>,
    ) -> Self
    where
        Table: NttTable<ValueT = T>,
    {
        assert_eq!(secret_key.poly_length(), table.poly_length());

        let size = RnsGlweSize::new(secret_key.glwe_size(), table.moduli_count());
        let poly_length = size.poly_length().get();
        let rns_poly_len = size.rns_poly_len();
        // Establish erasing ownership before writing secrets or invoking a
        // transform, so unwinding also erases a partially converted key.
        let mut key = Self {
            key: vec![T::ZERO; size.rns_mask_len()],
            distr: secret_key.distr(),
            size,
            moduli: table.iter().map(NttTable::modulus).collect(),
        };

        for (coefficients, mut dcrt_secret) in secret_key.iter().zip(DcrtPolynomialIterMut::new(
            key.key.as_mut_slice(),
            rns_poly_len,
        )) {
            for (ntt_table, modulus_limb) in table
                .iter()
                .zip(dcrt_secret.iter_each_modulus_mut(poly_length))
            {
                encode_secret_polynomial_to(coefficients, modulus_limb, ntt_table.modulus());
                ntt_table.transform_slice(modulus_limb);
            }
        }

        key
    }
}
