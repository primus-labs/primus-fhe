//! DCRT automorphism keeps the body in the evaluation domain. Each mask is
//! permuted, inverse-transformed for decomposition, then key-switched.
//!
//! [`NttAutomorphismPermutation`] owns the bit-reversed index map. This module
//! applies that same map independently to each ordered RNS modulus component.

use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_lattice::glev::{DcrtGlevIter, DcrtGlevIterMut};
use primus_ntt::{NttAutomorphismPermutation, NttTable};
use primus_poly::{DcrtPolynomial, NttPolynomialIter, NttPolynomialIterMut};
use primus_reduce::FieldContext;
use zeroize::Zeroizing;

use crate::RnsDomainError;
use crate::automorphism::{AutomorphismKeyMetadata, AutomorphismWorkspace};
use crate::{DcrtGadgetDomain, DcrtGlevEncryptor, DcrtGlweCiphertext, DcrtGlweSecretKey};

/// Applies one bit-reversed evaluation map to each DCRT modulus component.
/// The caller supplies complete, matching RNS polynomials; no arithmetic or
/// transform is performed here, so each component retains its residue range.
#[inline]
fn dcrt_polynomial_automorphism_to<T: FheUint>(
    input: &[T],
    output: &mut [T],
    permutation: &NttAutomorphismPermutation,
) {
    let n = permutation.poly_length().get();
    for (input, mut output) in
        NttPolynomialIter::new(input, n).zip(NttPolynomialIterMut::new(output, n))
    {
        permutation.apply_to(input.as_ref(), output.as_mut());
    }
}

/// Generate automorphism key data entirely in the NTT domain.
///
/// For each secret-key polynomial s_i (in NTT domain), apply NTT-domain
/// permutation σ_k(s_i) and encrypt under a GLEV ciphertext.
///
/// The caller binds the encryptor to this domain once and supplies one complete
/// DCRT scratch polynomial. Each row overwrites it in the existing NTT order;
/// no coefficient conversion or BFV scaling is performed.
fn generate_ntt_auto_key_data<T, M, Table, R>(
    domain: &DcrtGadgetDomain<'_, T, M, Table>,
    permutation: &NttAutomorphismPermutation,
    dcrt_sk: &DcrtGlweSecretKey<T>,
    encryptor: &DcrtGlevEncryptor<'_, T, M, Table>,
    auto_buffer: &mut [T],
    rng: &mut R,
) -> Vec<T>
where
    T: FheUint,
    Table: NttTable<ValueT = T>,
    R: rand::Rng + rand::CryptoRng,
    M: FieldContext<T>,
{
    let params = domain.parameters();
    let dcrt_glev_len = params.rns_glev_len();
    let mut key = vec![T::ZERO; params.dimension().get() * dcrt_glev_len];
    let mut auto_si = DcrtPolynomial(auto_buffer);

    let key_iter = DcrtGlevIterMut::new(key.as_mut_slice(), dcrt_glev_len);

    dcrt_sk
        .iter_dcrt_poly()
        .zip(key_iter)
        .for_each(|(si, mut dcrt_glev)| {
            dcrt_polynomial_automorphism_to(si.0, auto_si.as_mut(), permutation);

            encryptor.encrypt_dcrt_to(&auto_si, &mut dcrt_glev, rng);
        });

    key
}

/// Automorphism key for NTT-domain automorphism.
///
/// # Data flow (per automorphism evaluation)
///
/// For each `a_i` polynomial:
/// 1. NTT-domain permutation — O(N)
/// 2. INTT to coefficient domain — O(N log N), required for key-switch decomposition
/// 3. Key switch via external product
///
/// For the `b` polynomial:
/// 1. NTT-domain permutation — O(N), stays in NTT domain
#[derive(Clone)]
pub struct DcrtGlweAutoKey<T: FheUint> {
    data: DcrtGlweAutoKeyData<T>,
    metadata: AutomorphismKeyMetadata<T>,
}

impl<T: FheUint> DcrtGlweAutoKey<T> {
    /// Create a new NTT-domain automorphism key for the mapping x → x^degree.
    ///
    /// Key generation applies the NTT-domain permutation to each secret key
    /// polynomial and encrypts the result under a GLEV ciphertext. Only the
    /// NTT-domain secret key is needed.
    ///
    /// # Panics
    ///
    /// Panics if `degree` is not odd and less than twice the polynomial length.
    /// Also panics if the secret layout or ordered moduli do not match the domain.
    ///
    /// # Correctness
    /// Secrets must use the intended key and the domain table's NTT representation.
    #[must_use]
    pub fn new<M, Table, R>(
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        degree: usize,
        dcrt_sk: &DcrtGlweSecretKey<T>,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        Self {
            data: DcrtGlweAutoKeyData::new(domain, degree, dcrt_sk, rng),
            metadata: AutomorphismKeyMetadata::new(domain),
        }
    }
}

/// Encrypted transformed secret and its permutation, generated as one part of a
/// numerically homogeneous key set. The owner stores and validates its metadata.
#[derive(Clone)]
pub(super) struct DcrtGlweAutoKeyData<T: FheUint> {
    key: Vec<T>,
    permutation: NttAutomorphismPermutation,
}

impl<T: FheUint> DcrtGlweAutoKeyData<T> {
    /// Create a new NTT-domain automorphism key for the mapping x → x^degree.
    ///
    /// Key generation applies the NTT-domain permutation to each secret key
    /// polynomial and encrypts the result under a GLEV ciphertext. Only the
    /// NTT-domain secret key is needed.
    ///
    /// # Panics
    ///
    /// Panics if `degree` is invalid or the secret layout/ordered basis differs
    /// from the domain. These checks precede sampling.
    #[must_use]
    fn new<M, Table, R>(
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        degree: usize,
        dcrt_sk: &DcrtGlweSecretKey<T>,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let permutation =
            NttAutomorphismPermutation::new(degree, domain.parameters().poly_length());

        let encryptor = dcrt_sk
            .try_bind_gadget(domain)
            .expect("automorphism secret key and gadget domain are incompatible");
        let mut auto_buffer = Zeroizing::new(vec![T::ZERO; domain.parameters().rns_poly_len()]);
        let key = generate_ntt_auto_key_data(
            domain,
            &permutation,
            dcrt_sk,
            &encryptor,
            &mut auto_buffer,
            rng,
        );

        Self { key, permutation }
    }

    /// Generates a homogeneous key set in the supplied degree order. The DCRT
    /// key/domain binding precedes sampling; one NTT scratch polynomial serves
    /// all degrees and is erased on return/unwind. Each entry retains its own
    /// permutation and encrypted rows, with the original row/level RNG order.
    #[must_use]
    pub(super) fn generate_key_set<M, Table, R>(
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        degrees: impl Iterator<Item = usize>,
        dcrt_sk: &DcrtGlweSecretKey<T>,
        rng: &mut R,
    ) -> Vec<Self>
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let params = domain.parameters();
        let encryptor = dcrt_sk
            .try_bind_gadget(domain)
            .expect("automorphism secret key and gadget domain are incompatible");
        let mut auto_buffer = Zeroizing::new(vec![T::ZERO; params.rns_poly_len()]);

        degrees
            .map(|degree| {
                let permutation = NttAutomorphismPermutation::new(degree, params.poly_length());
                let key = generate_ntt_auto_key_data(
                    domain,
                    &permutation,
                    dcrt_sk,
                    &encryptor,
                    &mut auto_buffer,
                    rng,
                );
                Self { key, permutation }
            })
            .collect()
    }

    /// Internal kernel used by composed operations.
    /// Callers must ensure workspace compatibility and input/output layouts
    /// before invoking this kernel; it performs no boundary validation.
    pub(super) fn automorphism_kernel<M, Table>(
        &self,
        ciphertext: DcrtGlweCiphertext<&[T]>,
        mut result: DcrtGlweCiphertext<&mut [T]>,
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        workspace: &mut AutomorphismWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let params = domain.parameters();
        let table = domain.table();
        let rns_base = domain.rns_base();
        let poly_length = params.poly_length().get();
        let rns_poly_len = params.rns_poly_len();
        let moduli = params.cipher_moduli();

        let (auto_dcrt_poly, glev_workspace) = workspace.as_mut();

        result.set_zero();

        let (a_in, b_in) = ciphertext.a_b(rns_poly_len);

        // ----- Process a polynomials: NTT permutation → INTT → key switch -----
        DcrtGlevIter::new(self.key.as_slice(), params.rns_glev_len())
            .zip(a_in)
            .for_each(|(auto_key_i, in_dcrt_poly)| {
                // 1. NTT-domain permutation (evaluation-point reordering)
                dcrt_polynomial_automorphism_to(
                    in_dcrt_poly.as_ref(),
                    auto_dcrt_poly.as_mut(),
                    &self.permutation,
                );

                // 2. INTT → coefficient domain (required for key-switch decomposition)
                table.inverse_transform_slice(auto_dcrt_poly.as_mut());

                // 3. Key switch via external product
                result.add_dcrt_glev_mul_crt_polynomial_assign(
                    &auto_key_i,
                    auto_dcrt_poly,
                    params.basis(),
                    table,
                    rns_base,
                    glev_workspace,
                );
            });

        // ----- Process b polynomial: NTT permutation only (no transform needed) -----
        dcrt_polynomial_automorphism_to(b_in.as_ref(), auto_dcrt_poly.as_mut(), &self.permutation);

        // ----- Combine: result = (−a', σ(b) − b') -----
        let (a_out, mut b_out) = result.a_b_mut(rns_poly_len);

        a_out.for_each(|mut ai| ai.neg_assign(poly_length, moduli));

        DcrtPolynomial(auto_dcrt_poly.as_ref()).sub_rev_assign(&mut b_out, poly_length, moduli);
    }
}

/// DCRT automorphism, bound to one key, numerical domain and owned scratch.
///
/// Construct once and reuse. Numerical checks do not establish secret identity
/// or agreement on the table's NTT representation; callers maintain both.
/// Ciphertexts must contain canonical residues in the bound ordered Q basis.
pub struct DcrtGlweAutoEvaluator<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    key: &'a DcrtGlweAutoKey<T>,
    domain: &'a DcrtGadgetDomain<'a, T, M, Table>,
    workspace: AutomorphismWorkspace<T>,
}

impl<'a, T, M, Table> DcrtGlweAutoEvaluator<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    /// Creates a new [`DcrtGlweAutoEvaluator`] for a compatible key and domain.
    ///
    /// # Panics
    /// Panics if [`Self::try_new`] rejects the binding.
    #[must_use]
    pub fn new(key: &'a DcrtGlweAutoKey<T>, domain: &'a DcrtGadgetDomain<'a, T, M, Table>) -> Self {
        Self::try_new(key, domain)
            .unwrap_or_else(|error| panic!("invalid DCRT automorphism binding: {error}"))
    }

    /// Checks layout, ordered Q, radix and retained levels before allocating scratch.
    ///
    /// # Errors
    /// Returns [`RnsDomainError`] if the key and domain are numerically incompatible.
    pub fn try_new(
        key: &'a DcrtGlweAutoKey<T>,
        domain: &'a DcrtGadgetDomain<'a, T, M, Table>,
    ) -> Result<Self, RnsDomainError<T>> {
        key.metadata.validate(domain)?;
        let workspace = AutomorphismWorkspace::from_parameters(domain.parameters());
        Ok(Self {
            key,
            domain,
            workspace,
        })
    }

    /// Applies `X -> X^degree`, overwriting the complete output and internal scratch.
    ///
    /// # Correctness
    /// Both ciphertexts must have the bound domain's complete RNS GLWE layout and
    /// NTT representation, and use the secret for which the key was generated.
    pub fn automorphism_to<A: Data<Elem = T>, B: DataMut<Elem = T>>(
        &mut self,
        input: &DcrtGlweCiphertext<A>,
        output: &mut DcrtGlweCiphertext<B>,
    ) {
        let len = self.domain.parameters().rns_glwe_len();
        debug_assert_eq!(input.as_ref().len(), len);
        debug_assert_eq!(output.as_ref().len(), len);
        self.key.data.automorphism_kernel(
            input.as_view(),
            output.as_mut_view(),
            self.domain,
            &mut self.workspace,
        );
    }
}
