use itertools::izip;
use num_traits::ConstZero;
use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_lattice::glev::{DcrtGlevIter, DcrtGlevIterMut};
use primus_ntt::NttTable;
use primus_poly::{CoeffAutomorphismPermutation, CrtPolynomial, PolynomialIter, PolynomialIterMut};
use primus_reduce::FieldContext;
use zeroize::Zeroizing;

use crate::RnsDomainError;
use crate::automorphism::{AutomorphismKeyMetadata, AutomorphismWorkspace};
use crate::secret_key::encode_secret_polynomial_to_rns;
use crate::{
    CrtGlweCiphertext, DcrtGadgetDomain, DcrtGlevEncryptor, DcrtGlweCiphertext, DcrtGlweSecretKey,
    GlweSecretKey,
};

/// Encrypts each signed σ_k(s_i) after encoding it into the ordered CRT basis.
/// The caller binds the encryptor to this domain and checks the coefficient key
/// layout once. Both complete scratch polynomials are overwritten per key row.
fn generate_auto_key_data<T, M, Table, R>(
    domain: &DcrtGadgetDomain<'_, T, M, Table>,
    permutation: &CoeffAutomorphismPermutation,
    sk: &GlweSecretKey<T>,
    encryptor: &DcrtGlevEncryptor<'_, T, M, Table>,
    auto_signed: &mut [T::SignedInteger],
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
    let mut auto_si = CrtPolynomial(auto_buffer);

    let key_iter = DcrtGlevIterMut::new(key.as_mut_slice(), dcrt_glev_len);

    sk.iter().zip(key_iter).for_each(|(si, mut dcrt_glev)| {
        permutation.apply_signed_to::<T>(si, auto_signed);
        encode_secret_polynomial_to_rns(
            auto_signed,
            auto_si.as_mut(),
            params.cipher_moduli_value(),
        );

        encryptor.encrypt_crt_to(&auto_si, &mut dcrt_glev, rng);
    });

    key
}

/// Evaluation key for a coefficient-domain CRT automorphism.
#[derive(Clone)]
pub struct CrtGlweAutoKey<T: FheUint> {
    data: CrtGlweAutoKeyData<T>,
    metadata: AutomorphismKeyMetadata<T>,
}

impl<T: FheUint> CrtGlweAutoKey<T> {
    /// Creates an automorphism key for `X -> X^degree`.
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
        sk: &GlweSecretKey<T>,
        dcrt_sk: &DcrtGlweSecretKey<T>,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        Self {
            data: CrtGlweAutoKeyData::new(domain, degree, sk, dcrt_sk, rng),
            metadata: AutomorphismKeyMetadata::new(domain),
        }
    }
}

/// Encrypted transformed secret and its permutation, generated as one part of a
/// numerically homogeneous key set. The owner stores and validates its metadata.
#[derive(Clone)]
pub(super) struct CrtGlweAutoKeyData<T: FheUint> {
    key: Vec<T>,
    permutation: CoeffAutomorphismPermutation,
}

impl<T: FheUint> CrtGlweAutoKeyData<T> {
    /// Creates an automorphism key for `X -> X^degree`.
    ///
    /// # Panics
    ///
    /// Panics if `degree` is invalid or the secret layout/ordered basis differs
    /// from the domain. These checks precede sampling.
    #[must_use]
    fn new<M, Table, R>(
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        degree: usize,
        sk: &GlweSecretKey<T>,
        dcrt_sk: &DcrtGlweSecretKey<T>,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let permutation =
            CoeffAutomorphismPermutation::new(degree, domain.parameters().poly_length());

        let params = domain.parameters();
        let encryptor = dcrt_sk
            .try_bind_gadget(domain)
            .expect("automorphism secret key and gadget domain are incompatible");
        assert_eq!(sk.glwe_size(), params.size().rns_glwe_size().glwe_size());
        let mut auto_buffer = Zeroizing::new(vec![T::ZERO; params.rns_poly_len()]);
        let mut auto_signed =
            Zeroizing::new(vec![T::SignedInteger::ZERO; params.poly_length().get()]);
        let key = generate_auto_key_data(
            domain,
            &permutation,
            sk,
            &encryptor,
            &mut auto_signed,
            &mut auto_buffer,
            rng,
        );

        Self { key, permutation }
    }

    /// Generates a homogeneous key set in the supplied degree order. Binding
    /// and coefficient-key layout checks precede sampling; one signed and one
    /// CRT scratch polynomial serve all degrees and are erased on return/unwind.
    /// Every entry still owns its permutation and encrypted rows.
    #[must_use]
    pub(super) fn generate_key_set<M, Table, R>(
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        degrees: impl Iterator<Item = usize>,
        sk: &GlweSecretKey<T>,
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
        assert_eq!(sk.glwe_size(), params.size().rns_glwe_size().glwe_size());
        let mut auto_buffer = Zeroizing::new(vec![T::ZERO; params.rns_poly_len()]);
        let mut auto_signed =
            Zeroizing::new(vec![T::SignedInteger::ZERO; params.poly_length().get()]);

        degrees
            .map(|degree| {
                let permutation = CoeffAutomorphismPermutation::new(degree, params.poly_length());
                let key = generate_auto_key_data(
                    domain,
                    &permutation,
                    sk,
                    &encryptor,
                    &mut auto_signed,
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
        ciphertext: CrtGlweCiphertext<&[T]>,
        mut result: CrtGlweCiphertext<&mut [T]>,
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

        let permutation = &self.permutation;

        let (auto_crt_poly, glev_workspace) = workspace.as_mut();

        result.set_zero();
        let mut temp = DcrtGlweCiphertext::new(result.as_mut());

        let (a_in, b_in) = ciphertext.a_b(rns_poly_len);

        DcrtGlevIter::new(self.key.as_slice(), params.rns_glev_len())
            .zip(a_in)
            .for_each(|(auto_key_i, in_crt_poly)| {
                crt_polynomial_automorphism_to(
                    in_crt_poly.as_ref(),
                    auto_crt_poly.as_mut(),
                    permutation,
                    moduli,
                );

                temp.add_dcrt_glev_mul_crt_polynomial_assign(
                    &auto_key_i,
                    auto_crt_poly,
                    params.basis(),
                    table,
                    rns_base,
                    glev_workspace,
                );
            });

        crt_polynomial_automorphism_to(b_in.as_ref(), auto_crt_poly.as_mut(), permutation, moduli);

        let _ = temp.into_coeff_form(table);

        let (a_out, mut b_out) = result.a_b_mut(rns_poly_len);

        a_out.for_each(|mut ai| ai.neg_assign(poly_length, moduli));

        auto_crt_poly.sub_rev_assign(&mut b_out, poly_length, moduli);
    }
}

/// Applies one shared coefficient map to each ordered CRT modulus component.
/// The caller supplies complete, matching RNS polynomials and moduli.
fn crt_polynomial_automorphism_to<T, M>(
    input: &[T],
    output: &mut [T],
    permutation: &CoeffAutomorphismPermutation,
    moduli: &[M],
) where
    T: FheUint,
    M: FieldContext<T>,
{
    let n = permutation.poly_length().get();
    for (input, mut output, &modulus) in izip!(
        PolynomialIter::new(input, n),
        PolynomialIterMut::new(output, n),
        moduli
    ) {
        permutation.apply_to(input.as_ref(), output.as_mut(), modulus);
    }
}

/// CRT automorphism, bound to one key, numerical domain and owned scratch.
///
/// Construct once and reuse. Numerical checks do not establish secret identity
/// or agreement on the table's NTT representation; callers maintain both.
/// Ciphertexts must contain canonical residues in the bound ordered Q basis.
pub struct CrtGlweAutoEvaluator<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    key: &'a CrtGlweAutoKey<T>,
    domain: &'a DcrtGadgetDomain<'a, T, M, Table>,
    workspace: AutomorphismWorkspace<T>,
}

impl<'a, T, M, Table> CrtGlweAutoEvaluator<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    /// Creates a new [`CrtGlweAutoEvaluator`] for a compatible key and domain.
    ///
    /// # Panics
    /// Panics if [`Self::try_new`] rejects the binding.
    #[must_use]
    pub fn new(key: &'a CrtGlweAutoKey<T>, domain: &'a DcrtGadgetDomain<'a, T, M, Table>) -> Self {
        Self::try_new(key, domain)
            .unwrap_or_else(|error| panic!("invalid CRT automorphism binding: {error}"))
    }

    /// Checks layout, ordered Q, radix and retained levels before allocating scratch.
    ///
    /// # Errors
    /// Returns [`RnsDomainError`] if the key and domain are numerically incompatible.
    pub fn try_new(
        key: &'a CrtGlweAutoKey<T>,
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
    /// coefficient representation, and use the secret for which the key was generated.
    pub fn automorphism_to<A: Data<Elem = T>, B: DataMut<Elem = T>>(
        &mut self,
        input: &CrtGlweCiphertext<A>,
        output: &mut CrtGlweCiphertext<B>,
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
