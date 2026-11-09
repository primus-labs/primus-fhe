//! Undecoded coefficient-phase extraction (`f * c`).

use super::NttNtruSecretKey;
use crate::NttNtruCiphertext;
use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{NttPolynomial, Polynomial};
use primus_reduce::FieldContext;

impl<T: FheUint> NttNtruSecretKey<T> {
    /// Computes `f * c` and writes `mu + e` for an encoded message `mu` in coefficient form.
    /// The output is an undecoded coefficient polynomial; no plaintext codec or
    /// noise distribution is needed. Output is overwritten, including old values.
    ///
    /// # Correctness
    ///
    /// The input and key must use the supplied table's NTT representation, with
    /// canonical residues modulo `modulus`.
    ///
    /// # Panics
    ///
    /// Panics before writes if transform, input or output lengths do not match
    /// the key, or if the key, table and arithmetic moduli disagree.
    pub fn decrypt_phase_to<M, Table, A, B>(
        &self,
        input: &NttNtruCiphertext<A>,
        output: &mut Polynomial<B>,
        modulus: M,
        ntt_table: &Table,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.assert_ntt_compatible(modulus, ntt_table);
        assert_eq!(input.as_ref().len(), self.poly_length());
        assert_eq!(output.as_ref().len(), self.poly_length());

        NttPolynomial(input.as_ref()).mul_to(
            &self.key,
            &mut NttPolynomial(output.as_mut()),
            modulus,
        );
        ntt_table.inverse_transform_slice(output.as_mut());
    }
}
