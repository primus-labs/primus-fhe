//! GLev encryption, preserving coefficient/NTT message scaling order.

use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_lattice::glev::DcrtGlev;
use primus_ntt::NttTable;
use primus_poly::{CrtPolynomial, DcrtPolynomial};
use primus_reduce::FieldContext;
use primus_rns::Residues;

use super::DcrtGlevEncryptor;
use crate::DcrtGlweCiphertext;

impl<T, M, Table> DcrtGlevEncryptor<'_, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    /// Encrypts a DCRT plaintext polynomial into an existing DCRT GLev allocation.
    ///
    /// The plaintext has one complete RNS polynomial; the output has the bound
    /// GLev layout. Both use the bound ordered basis and NTT representation.
    /// Gadget weights are applied without BFV plaintext scaling.
    pub fn encrypt_dcrt_to<R, A, B>(
        &self,
        input: &DcrtPolynomial<A>,
        output: &mut DcrtGlev<B>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let domain = self.domain;
        let parameters = domain.parameters();
        debug_assert_eq!(output.as_ref().len(), parameters.rns_glev_len());
        self.encrypt_dcrt_glev_kernel_to(input.as_view(), output.as_mut_view(), rng);
    }

    /// Encrypts a CRT plaintext polynomial into an existing DCRT GLev allocation.
    ///
    /// The message has one complete coefficient-domain RNS polynomial; the
    /// output is overwritten using the bound GLev layout.
    /// Gadget weights are applied without BFV plaintext scaling.
    pub fn encrypt_crt_to<R, A, B>(
        &self,
        input: &CrtPolynomial<A>,
        output: &mut DcrtGlev<B>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let domain = self.domain;
        let parameters = domain.parameters();
        debug_assert_eq!(output.as_ref().len(), parameters.rns_glev_len());
        self.encrypt_crt_glev_kernel_to(input.as_view(), output.as_mut_view(), rng);
    }

    /// Transforms coefficient noise before adding the scaled evaluation-domain message.
    /// Operands and residues must use complete layouts in the parameter/table basis order.
    /// The caller owns these preconditions; this helper performs no boundary validation.
    fn encrypt_dcrt_glwe_with_scale_to<R>(
        &self,
        input: DcrtPolynomial<&[T]>,
        delta_residues: Residues<&[T]>,
        mut output: DcrtGlweCiphertext<&mut [T]>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.domain.parameters();
        let table = self.domain.table();
        let poly_length = parameters.poly_length().get();
        let moduli = parameters.cipher_moduli();
        let uniform_distrs = parameters.cipher_moduli_uniform_distr();

        let (a, mut b) = output.a_b_mut(parameters.rns_poly_len());

        primus_distr::sample_crt_gaussian_values_to(
            b.as_mut(),
            poly_length,
            parameters.cipher_moduli_value(),
            parameters.noise_distribution(),
            &mut *rng,
        );

        table.transform_slice(b.as_mut());
        b.add_mul_scalar_assign(&input, delta_residues.as_ref(), poly_length, moduli);

        self.key.iter_dcrt_poly().zip(a).for_each(|(si, mut ai)| {
            primus_distr::sample_crt_uniform_values_to(
                ai.as_mut(),
                poly_length,
                uniform_distrs,
                &mut *rng,
            );
            b.add_mul_assign(&ai, &si, poly_length, moduli);
        });
    }

    /// Reuses the DCRT message at every gadget level, adding it after the noise
    /// transform. The encryptor establishes the key/domain numerical binding;
    /// message/output layouts and representations remain caller contracts.
    fn encrypt_dcrt_glev_kernel_to<R>(
        &self,
        input: DcrtPolynomial<&[T]>,
        mut output: DcrtGlev<&mut [T]>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.domain.parameters();
        output
            .iter_dcrt_glwe_mut(parameters.rns_glwe_len())
            .zip(parameters.scalar_residue_iter())
            .for_each(|(dcrt_glwe, scalar_residues)| {
                self.encrypt_dcrt_glwe_with_scale_to(
                    input.as_view(),
                    scalar_residues.view(),
                    dcrt_glwe,
                    rng,
                );
            });
    }

    /// Scales the message in coefficient form before the body transform.
    /// Operands and residues must use complete layouts in the parameter/table basis order.
    /// The caller owns these preconditions; this helper performs no boundary validation.
    fn encrypt_crt_glwe_with_scale_to<R>(
        &self,
        input: CrtPolynomial<&[T]>,
        delta_residues: Residues<&[T]>,
        mut output: DcrtGlweCiphertext<&mut [T]>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.domain.parameters();
        let table = self.domain.table();
        let poly_length = parameters.poly_length().get();
        let moduli = parameters.cipher_moduli();
        let uniform_distrs = parameters.cipher_moduli_uniform_distr();

        let (a, mut b) = output.a_b_mut(parameters.rns_poly_len());

        primus_distr::sample_crt_gaussian_values_to(
            b.as_mut(),
            poly_length,
            parameters.cipher_moduli_value(),
            parameters.noise_distribution(),
            &mut *rng,
        );

        let mut b_crt_poly = CrtPolynomial(b.as_mut());
        b_crt_poly.add_mul_scalar_assign(&input, delta_residues.as_ref(), poly_length, moduli);
        table.transform_slice(b.as_mut());

        self.key.iter_dcrt_poly().zip(a).for_each(|(si, mut ai)| {
            primus_distr::sample_crt_uniform_values_to(
                ai.as_mut(),
                poly_length,
                uniform_distrs,
                &mut *rng,
            );
            b.add_mul_assign(&ai, &si, poly_length, moduli);
        });
    }

    /// Reuses the CRT message at every gadget level, adding it before the body
    /// transform. The encryptor establishes the key/domain numerical binding;
    /// message/output layouts and representations remain caller contracts.
    fn encrypt_crt_glev_kernel_to<R>(
        &self,
        input: CrtPolynomial<&[T]>,
        mut output: DcrtGlev<&mut [T]>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.domain.parameters();
        output
            .iter_dcrt_glwe_mut(parameters.rns_glwe_len())
            .zip(parameters.scalar_residue_iter())
            .for_each(|(dcrt_glwe, scalar_residues)| {
                self.encrypt_crt_glwe_with_scale_to(
                    input.as_view(),
                    scalar_residues.view(),
                    dcrt_glwe,
                    rng,
                );
            });
    }
}
