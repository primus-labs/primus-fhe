//! Codec-free secret binding, raw encryption and additive phase shares.

use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_lattice::RnsGlweSize;
use primus_ntt::{DcrtTable, NttTable};
use primus_poly::{CrtPolynomial, DcrtPolynomial};
use primus_reduce::FieldContext;
use primus_rns::RNSBase;

use super::DcrtGlweSecretKey;
use crate::{CrtGlweEncryptionParameters, DcrtGlweCiphertext, DcrtGlweDomain, RnsDomainError};

/// A secret key bound to codec-free sampling, an ordered RNS base and a table.
///
/// Construct with [`DcrtGlweSecretKey::try_bind_raw`]. The binding borrows its
/// resources without cloning the key or allocating scratch. It provides raw
/// phase arithmetic, not plaintext recovery or a private distributed opening.
pub struct DcrtGlweRawSecretKeyContext<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    key: &'a DcrtGlweSecretKey<T>,
    domain: &'a DcrtGlweDomain<'a, T, M, Table>,
}

impl<T: FheUint> DcrtGlweSecretKey<T> {
    /// Binds this secret to a checked codec-free GLWE domain.
    ///
    /// # Errors
    /// Returns [`RnsDomainError`] if the key layout or ordered moduli differ
    /// from the domain. Equal moduli do not establish NTT representation identity;
    /// the secret and table must use the same roots and evaluation order.
    pub fn try_bind_raw<'a, M, Table>(
        &'a self,
        domain: &'a DcrtGlweDomain<'a, T, M, Table>,
    ) -> Result<DcrtGlweRawSecretKeyContext<'a, T, M, Table>, RnsDomainError<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        self.validate_parameters(domain.size(), domain.rns_base().moduli())?;
        Ok(DcrtGlweRawSecretKeyContext { key: self, domain })
    }
}

impl<T, M, Table> DcrtGlweRawSecretKeyContext<'_, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    /// Encrypts zero, overwriting the complete output in DCRT form.
    ///
    /// No plaintext or gadget scale is applied. One coefficient noise sample is
    /// lifted consistently across the ordered RNS limbs; the body is transformed
    /// once before adding the uniform-mask/secret products. No scratch is allocated.
    ///
    /// # Panics
    /// Panics before sampling or writes if output length differs from the bound
    /// GLWE layout. RNG/transform panics can leave partially written output.
    pub fn encrypt_zeros_to<R, A>(&self, output: &mut DcrtGlweCiphertext<A>, rng: &mut R)
    where
        R: rand::Rng + rand::CryptoRng,
        A: DataMut<Elem = T>,
    {
        self.assert_output_length(output.as_ref().len());
        encrypt_kernel_to(
            self.key,
            self.domain.parameters(),
            self.domain.rns_base(),
            self.domain.table(),
            output.as_mut_view(),
            rng,
            |_| {},
        );
    }

    /// Encrypts an already-encoded coefficient-domain CRT phase polynomial.
    ///
    /// The input has exactly one complete RNS polynomial in the domain's modulus
    /// order, with canonical coefficients in each limb. It is added directly to
    /// coefficient noise before the body's single NTT; neither BFV scaling nor
    /// gadget weights are applied. Output is overwritten without scratch allocation.
    ///
    /// # Correctness
    /// The caller supplies the intended encoded phase and canonical residues;
    /// this operation does not validate its message semantics or noise margin.
    ///
    /// # Panics
    /// Panics before sampling or writes for incorrect input/output lengths.
    /// RNG/transform panics can leave partially written output.
    pub fn encrypt_encoded_crt_to<R, A, B>(
        &self,
        input: &CrtPolynomial<A>,
        output: &mut DcrtGlweCiphertext<B>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let size = self.domain.size();
        assert_eq!(
            input.as_ref().len(),
            size.rns_poly_len(),
            "encoded CRT phase length mismatch"
        );
        self.assert_output_length(output.as_ref().len());
        encrypt_kernel_to(
            self.key,
            self.domain.parameters(),
            self.domain.rns_base(),
            self.domain.table(),
            output.as_mut_view(),
            rng,
            |body| {
                body.add_assign(
                    input,
                    size.poly_length().get(),
                    self.domain.rns_base().moduli(),
                )
            },
        );
    }

    /// Writes the complete DCRT phase `b - sum(a_i*s_i)`.
    ///
    /// Inputs and output use the bound ordered basis and NTT representation.
    /// Output is overwritten; no inverse transform, decoding or allocation occurs.
    ///
    /// # Correctness
    /// Input canonical residues and NTT representation must match this secret.
    ///
    /// # Panics
    /// Panics before writes if either complete input or output length is wrong.
    pub fn phase_to<A, B>(&self, input: &DcrtGlweCiphertext<A>, output: &mut DcrtPolynomial<B>)
    where
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.phase_to_with_body(input, output, true);
    }

    /// Writes the additive DCRT share `-sum(a_i*s_i)`, excluding the body.
    ///
    /// For additive secret shares, sum these outputs and add the ciphertext body
    /// exactly once. Equivalently, one party may use [`Self::phase_to`] and the
    /// others this method. This raw arithmetic adds no privacy noise or one-use
    /// guard; distributed opening policy belongs to the calling protocol.
    ///
    /// Output is overwritten. The ciphertext's complete layout is required even
    /// though its body is ignored; representation requirements match [`Self::phase_to`].
    ///
    /// # Panics
    /// Panics before writes if either complete input or output length is wrong.
    pub fn partial_phase_to<A, B>(
        &self,
        input: &DcrtGlweCiphertext<A>,
        output: &mut DcrtPolynomial<B>,
    ) where
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.phase_to_with_body(input, output, false);
    }

    fn assert_output_length(&self, length: usize) {
        assert_eq!(
            length,
            self.domain.size().rns_glwe_len(),
            "raw DCRT GLWE output length mismatch"
        );
    }

    fn phase_to_with_body<A, B>(
        &self,
        input: &DcrtGlweCiphertext<A>,
        output: &mut DcrtPolynomial<B>,
        include_body: bool,
    ) where
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let size = self.domain.size();
        assert_eq!(
            input.as_ref().len(),
            size.rns_glwe_len(),
            "raw DCRT GLWE input length mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            size.rns_poly_len(),
            "DCRT phase output length mismatch"
        );
        phase_kernel_to(
            self.key,
            size,
            self.domain.rns_base().moduli(),
            input.as_view(),
            output.as_mut_view(),
            include_body,
        );
    }
}

/// Shared body/mask encryption kernel. The owning context has established layout,
/// base/table order and transform identity; injection fuses into coefficient noise.
pub(super) fn encrypt_kernel_to<T, M, Table, R>(
    key: &DcrtGlweSecretKey<T>,
    parameters: &CrtGlweEncryptionParameters<T>,
    rns_base: &RNSBase<T, M>,
    table: &DcrtTable<Table>,
    mut output: DcrtGlweCiphertext<&mut [T]>,
    rng: &mut R,
    inject_phase: impl FnOnce(&mut CrtPolynomial<&mut [T]>),
) where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
    R: rand::Rng + rand::CryptoRng,
{
    let size = parameters.size();
    let poly_length = size.poly_length().get();
    let (a, mut b) = output.a_b_mut(size.rns_poly_len());
    parameters.sample_noise_to(b.as_mut(), rns_base.moduli_values(), rng);
    inject_phase(&mut CrtPolynomial(b.as_mut()));
    table.transform_slice(b.as_mut());
    key.iter_dcrt_poly().zip(a).for_each(|(secret, mut mask)| {
        primus_distr::sample_crt_uniform_values_to(
            mask.as_mut(),
            poly_length,
            parameters.cipher_moduli_uniform_distr(),
            rng,
        );
        b.add_mul_assign(&mask, &secret, poly_length, rns_base.moduli());
    });
}

/// Shared full/partial phase kernel; the caller establishes complete layouts.
pub(super) fn phase_kernel_to<T, M>(
    key: &DcrtGlweSecretKey<T>,
    size: RnsGlweSize,
    moduli: &[M],
    input: DcrtGlweCiphertext<&[T]>,
    mut output: DcrtPolynomial<&mut [T]>,
    include_body: bool,
) where
    T: FheUint,
    M: FieldContext<T>,
{
    let (a, b) = input.a_b(size.rns_poly_len());
    output.set_zero();
    for (secret, mask) in key.iter_dcrt_poly().zip(a) {
        output.add_mul_assign(&mask, &secret, size.poly_length().get(), moduli);
    }
    if include_body {
        b.sub_rev_assign(&mut output, size.poly_length().get(), moduli);
    } else {
        output.neg_assign(size.poly_length().get(), moduli);
    }
}
