//! NTT GLWE phase extraction without message decoding.

use super::NttGlweSecretKey;
use crate::NttGlweCiphertext;
use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{NttPolynomial, Polynomial};
use primus_reduce::FieldContext;

impl<T: FheUint> NttGlweSecretKey<T> {
    /// Performs `b - ∑ a_i * s_i` (phase), leaving output in coefficient domain.
    ///
    /// # Correctness
    ///
    /// Input values must be canonical residues modulo `modulus`, in the same
    /// NTT representation as this key and `ntt_table`.
    ///
    /// # Panics
    ///
    /// Panics if ciphertext/output/table lengths do not match the key layout,
    /// or the key, arithmetic and table moduli differ. Checks precede output writes.
    pub fn decrypt_phase_to<M, Table, A, B>(
        &self,
        input: &NttGlweCiphertext<A>,
        output: &mut Polynomial<B>,
        modulus: M,
        ntt_table: &Table,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let poly_length = self.size.poly_length().get();
        self.assert_ntt_compatible(modulus, ntt_table);
        assert_eq!(
            output.as_ref().len(),
            poly_length,
            "GLWE phase output length mismatch"
        );
        assert_eq!(
            input.as_ref().len(),
            self.size.glwe_len(),
            "GLWE input layout mismatch"
        );

        let (mut a, b) = input.a_b(poly_length);
        let mut secret = self.iter();

        let mut result_poly = NttPolynomial(output.as_mut());
        let si = secret.next().expect("GLWE dimension must be non-zero");
        let ai = a.next().expect("GLWE ciphertext mask is missing");

        ai.mul_to(&si, &mut result_poly, modulus);

        secret.zip(a).for_each(|(si, ai)| {
            result_poly.add_mul_assign(&ai, &si, modulus);
        });
        b.sub_rev_assign(&mut result_poly, modulus);

        ntt_table.inverse_transform_slice(output.as_mut())
    }
}
