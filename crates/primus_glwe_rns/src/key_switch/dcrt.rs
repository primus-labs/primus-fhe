//! GLWE key switching with signed digit decomposition over an RNS basis.

use crate::parameter::{validate_glwe_size, validate_moduli};
use primus_data::{Data, DataMut};
use primus_decompose::DecompositionBaseLog;
use primus_integer::FheUint;
use primus_lattice::{
    RnsGadgetSize, RnsGlweSize,
    glev::{DcrtGlevIter, DcrtGlevIterMut},
    workspace::DcrtGlevMulWorkspace,
};
use primus_ntt::NttTable;
use primus_poly::{CrtPolynomial, DcrtPolynomial};
use primus_reduce::FieldContext;
use zeroize::Zeroizing;

use crate::secret_key::encode_secret_polynomial_to_rns;
use crate::{
    CrtGlweCiphertext, CrtGlweEncryptionParameters, DcrtGadgetDomain, DcrtGlweCiphertext,
    DcrtGlweSecretKey, GlweSecretKey, RnsDomainError,
};

/// A DCRT GLWE key-switching key stored as input-mask-ordered GLev entries.
pub struct DcrtGlweKeySwitchingKey<T: FheUint> {
    key: Vec<T>,
    input_size: RnsGlweSize,
    output_size: RnsGadgetSize,
    moduli: Vec<T>,
    log_basis: DecompositionBaseLog,
}

impl<T: FheUint> DcrtGlweKeySwitchingKey<T> {
    /// Generates a key from a coefficient-domain input key to a DCRT output key.
    /// Input layout and ordered Q come from codec-free sampling parameters; output
    /// noise and gadget scales come from the bound output domain.
    ///
    /// # Panics
    /// Panics if secret layouts, polynomial lengths or ordered moduli are
    /// incompatible, or if the combined key storage length overflows. Checks
    /// precede random sampling.
    ///
    /// # Correctness
    /// Input coefficients must fit the ordered moduli, and both keys must use
    /// the intended secrets and the table's NTT representation.
    pub fn generate<R, M, Table>(
        input_sk: &GlweSecretKey<T>,
        input_params: &CrtGlweEncryptionParameters<T>,
        output_sk: &DcrtGlweSecretKey<T>,
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let ksk_params = domain.parameters();
        input_params
            .validate_base(domain.rns_base())
            .expect("DCRT key-switch input parameters and output domain are incompatible");
        assert_eq!(
            input_params.size().poly_length(),
            domain.size().rns_glwe_size().poly_length(),
            "DCRT key-switch input and output polynomial lengths differ"
        );
        let encryptor = output_sk
            .try_bind_gadget(domain)
            .expect("DCRT key-switch output secret and domain are incompatible");
        assert_eq!(input_sk.glwe_size(), input_params.size().glwe_size());

        let dcrt_glev_len = ksk_params.rns_glev_len();
        let key_len = input_params
            .size()
            .dimension()
            .get()
            .checked_mul(dcrt_glev_len)
            .expect("DCRT GLWE key-switching key length overflow");
        let mut key = vec![T::ZERO; key_len];

        let key_iter = DcrtGlevIterMut::new(key.as_mut_slice(), dcrt_glev_len);
        let mut secret_buffer = Zeroizing::new(vec![T::ZERO; input_params.size().rns_poly_len()]);
        let mut secret_mod_q = CrtPolynomial(secret_buffer.as_mut_slice());

        input_sk
            .iter()
            .zip(key_iter)
            .for_each(|(secret_polynomial, mut dcrt_glev)| {
                encode_secret_polynomial_to_rns(
                    secret_polynomial,
                    secret_mod_q.as_mut(),
                    ksk_params.cipher_moduli_value(),
                );
                encryptor.encrypt_crt_to(&secret_mod_q, &mut dcrt_glev, rng);
            });

        Self {
            key,
            input_size: input_params.size(),
            output_size: ksk_params.size(),
            moduli: ksk_params.cipher_moduli_value().to_vec(),
            log_basis: ksk_params.basis().log_basis(),
        }
    }

    /// Returns the input ciphertext sizes bound to this key.
    #[must_use]
    #[inline]
    pub fn input_size(&self) -> RnsGlweSize {
        self.input_size
    }

    /// Returns the output gadget sizes bound to this key.
    #[must_use]
    #[inline]
    pub fn output_size(&self) -> RnsGadgetSize {
        self.output_size
    }

    pub(crate) fn iter_dcrt_glev(&self) -> DcrtGlevIter<'_, T> {
        DcrtGlevIter::new(self.key.as_slice(), self.output_size.rns_glev_len())
    }

    /// Uses the evaluator's established key/domain/workspace binding. Operand layouts
    /// and representation remain caller contracts; no numerical rebinding occurs here.
    fn key_switch_kernel_to<M, Table>(
        &self,
        input: CrtGlweCiphertext<&[T]>,
        mut output: DcrtGlweCiphertext<&mut [T]>,
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        workspace: &mut DcrtGlweKeySwitchingWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let parameters = domain.parameters();
        let table = domain.table();
        let rns_base = domain.rns_base();
        let basis = parameters.basis();
        let poly_length = self.input_size.poly_length().get();
        let rns_poly_len = self.input_size.rns_poly_len();
        let DcrtGlweKeySwitchingWorkspace {
            transformed_polynomial,
            glev_workspace,
            ..
        } = workspace;

        let (input_mask, input_body) = input.a_b(rns_poly_len);

        output.set_zero();
        self.iter_dcrt_glev()
            .zip(input_mask)
            .for_each(|(key_entry, mask_polynomial)| {
                // Compose directly into the decomposition workspace; the CRT
                // entry point adjusts it in place and overwrites every buffer.
                output.add_dcrt_glev_mul_crt_polynomial_assign(
                    &key_entry,
                    &mask_polynomial,
                    basis,
                    table,
                    rns_base,
                    glev_workspace,
                );
            });

        transformed_polynomial.copy_from(&input_body);
        table.transform_slice(transformed_polynomial.as_mut());
        output.neg_assign(poly_length, rns_poly_len, rns_base.moduli());

        let (_, output_body) = output.a_b_mut_slices(rns_poly_len);
        DcrtPolynomial(output_body).add_assign(
            &DcrtPolynomial(transformed_polynomial.as_ref()),
            poly_length,
            rns_base.moduli(),
        );
    }
}

/// DCRT key switching bound to its key, numerical domain and owned workspace.
///
/// Construct once with [`Self::try_new`] and reuse for all compatible inputs.
/// Inputs must use the key's secret and coefficient representation; modulus
/// checks do not prove secret identity or agreement on a table's NTT representation.
pub struct DcrtGlweKeySwitchEvaluator<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    key: &'a DcrtGlweKeySwitchingKey<T>,
    domain: &'a DcrtGadgetDomain<'a, T, M, Table>,
    workspace: DcrtGlweKeySwitchingWorkspace<T>,
}

impl<'a, T, M, Table> DcrtGlweKeySwitchEvaluator<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    /// Creates a new [`DcrtGlweKeySwitchEvaluator`] for a compatible key and domain.
    ///
    /// # Panics
    /// Panics if [`Self::try_new`] rejects the binding.
    #[must_use]
    pub fn new(
        key: &'a DcrtGlweKeySwitchingKey<T>,
        domain: &'a DcrtGadgetDomain<'a, T, M, Table>,
    ) -> Self {
        Self::try_new(key, domain)
            .unwrap_or_else(|error| panic!("invalid DCRT key-switch binding: {error}"))
    }

    /// Binds the key and domain before allocating reusable scratch.
    ///
    /// # Errors
    /// Returns [`RnsDomainError`] for a different gadget layout, ordered basis or radix.
    pub fn try_new(
        key: &'a DcrtGlweKeySwitchingKey<T>,
        domain: &'a DcrtGadgetDomain<'a, T, M, Table>,
    ) -> Result<Self, RnsDomainError<T>> {
        validate_glwe_size(
            key.output_size.rns_glwe_size(),
            domain.size().rns_glwe_size(),
        )?;
        let expected = key.output_size.level_count().get();
        let actual = domain.size().level_count().get();
        if expected != actual {
            return Err(RnsDomainError::DecompositionLevelCountMismatch { expected, actual });
        }
        validate_moduli(
            key.moduli.iter().copied(),
            domain.parameters().cipher_moduli_value().iter().copied(),
        )?;
        if key.log_basis != domain.basis().log_basis() {
            return Err(RnsDomainError::DecompositionBaseLogMismatch {
                expected: key.log_basis.get(),
                actual: domain.basis().log_basis().get(),
            });
        }
        let workspace = DcrtGlweKeySwitchingWorkspace {
            transformed_polynomial: CrtPolynomial::zero(key.input_size.rns_poly_len()),
            glev_workspace: DcrtGlevMulWorkspace::new(key.output_size, domain.rns_base()),
        };
        Ok(Self {
            key,
            domain,
            workspace,
        })
    }

    /// Switches a coefficient-domain input to a DCRT output, overwriting it.
    ///
    /// # Correctness
    /// Input and output must have the key's complete input/output layouts.
    /// The caller maintains the input secret identity and table representation.
    pub fn key_switch_to<A: Data<Elem = T>, B: DataMut<Elem = T>>(
        &mut self,
        input: &CrtGlweCiphertext<A>,
        output: &mut DcrtGlweCiphertext<B>,
    ) {
        debug_assert_eq!(input.as_ref().len(), self.key.input_size.rns_glwe_len());
        debug_assert_eq!(
            output.as_ref().len(),
            self.key.output_size.rns_glwe_size().rns_glwe_len()
        );
        self.key.key_switch_kernel_to(
            input.as_view(),
            output.as_mut_view(),
            self.domain,
            &mut self.workspace,
        );
    }
}

/// Owned scratch with no independent key or domain binding; the evaluator owns that contract.
struct DcrtGlweKeySwitchingWorkspace<T: FheUint> {
    transformed_polynomial: CrtPolynomial<Vec<T>>,
    glev_workspace: DcrtGlevMulWorkspace<T>,
}
