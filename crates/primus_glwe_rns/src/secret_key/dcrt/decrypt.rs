//! DCRT phase extraction, coefficient recovery and BFV decoding.

use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{CrtPolynomial, DcrtPolynomial, Polynomial, PolynomialOwned};
use primus_reduce::FieldContext;

use super::{DcrtGlweDecryptWorkspace, DcrtGlweSecretKeyContext};
use crate::DcrtGlweCiphertext;

impl<T, M, Table> DcrtGlweSecretKeyContext<'_, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    /// Performs `b - ∑ a*s` from a complete bound-layout GLWE input.
    /// Overwrites one complete DCRT polynomial in `phase`.
    pub fn phase_to<A, B>(&self, input: &DcrtGlweCiphertext<A>, phase: &mut DcrtPolynomial<B>)
    where
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.phase_kernel_to(input.as_view(), phase.as_mut_view());
    }

    /// Decrypts a DCRT GLWE input into a newly allocated plaintext polynomial.
    #[must_use]
    pub fn decrypt<A>(
        &self,
        input: &DcrtGlweCiphertext<A>,
        workspace: &mut DcrtGlweDecryptWorkspace<T>,
    ) -> PolynomialOwned<T>
    where
        A: Data<Elem = T>,
    {
        let parameters = self.parameters;
        let mut output = PolynomialOwned::zero(parameters.poly_length().get());
        self.decrypt_to(input, &mut output, workspace);
        output
    }

    /// Decrypts a DCRT GLWE input into `output` using reusable workspace.
    ///
    /// The input and workspace use the bound parameters' GLWE layout;
    /// `output` has N coefficients. The input must use this key and NTT representation.
    pub fn decrypt_to<A, B>(
        &self,
        input: &DcrtGlweCiphertext<A>,
        output: &mut Polynomial<B>,
        workspace: &mut DcrtGlweDecryptWorkspace<T>,
    ) where
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let parameters = self.parameters;
        debug_assert_eq!(workspace.size(), parameters.size());
        self.decrypt_kernel_to(input.as_view(), output.as_mut_view(), workspace);
    }

    /// Computes the DCRT phase with complete, matching layouts in parameter basis order.
    fn phase_kernel_to(
        &self,
        input: DcrtGlweCiphertext<&[T]>,
        mut phase: DcrtPolynomial<&mut [T]>,
    ) {
        let parameters = self.parameters;
        let poly_length = parameters.poly_length().get();
        let moduli = parameters.cipher_moduli();

        let (a, b) = input.a_b(parameters.rns_poly_len());

        phase.set_zero();

        self.key.iter_dcrt_poly().zip(a).for_each(|(si, ai)| {
            phase.add_mul_assign(&ai, &si, poly_length, moduli);
        });

        b.sub_rev_assign(&mut phase, poly_length, moduli);
    }

    /// Uses an erasing workspace whose shape matches the bound parameters.
    /// Operand layouts and transform identity remain caller contracts. Phase extraction
    /// overwrites scratch before inverse transformation and BFV decoding.
    fn decrypt_kernel_to(
        &self,
        input: DcrtGlweCiphertext<&[T]>,
        mut output: Polynomial<&mut [T]>,
        workspace: &mut DcrtGlweDecryptWorkspace<T>,
    ) {
        let (phase, fast_convert_buffer) = workspace.as_mut();

        self.phase_kernel_to(input, phase.as_mut_view());

        self.table.inverse_transform_slice(phase.as_mut());

        self.parameters.codec().decode_coeffs_to(
            &mut CrtPolynomial(phase.as_mut()),
            &mut output,
            fast_convert_buffer,
        );
    }
}
