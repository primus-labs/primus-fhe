use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_reduce::FieldContext;

use super::automorphism::CrtGlweAutoKeyData;
use crate::RnsDomainError;
use crate::automorphism::{AutomorphismKeyMetadata, AutomorphismWorkspace};
use crate::{
    CrtGlevParameters, CrtGlweCiphertext, DcrtGadgetDomain, DcrtGlweSecretKey, GlweSecretKey,
};

/// Owned ciphertext and automorphism scratch for bound trace/expansion operations.
pub(super) struct CrtGlweTraceWorkspace<T: FheUint> {
    crt_glwe: CrtGlweCiphertext<Vec<T>>,
    auto_workspace: AutomorphismWorkspace<T>,
}

impl<T: FheUint> CrtGlweTraceWorkspace<T> {
    pub(crate) fn from_parameters<M>(parameters: &CrtGlevParameters<T, M>) -> Self
    where
        M: FieldContext<T>,
    {
        let crt_glwe = CrtGlweCiphertext::zero(parameters.rns_glwe_len());
        let auto_workspace = AutomorphismWorkspace::from_parameters(parameters);
        Self {
            crt_glwe,
            auto_workspace,
        }
    }

    pub(crate) fn as_mut(
        &mut self,
    ) -> (
        &mut CrtGlweCiphertext<Vec<T>>,
        &mut AutomorphismWorkspace<T>,
    ) {
        (&mut self.crt_glwe, &mut self.auto_workspace)
    }
}

#[derive(Clone)]
/// Automorphism keys for the full ring trace of CRT GLWE ciphertexts.
pub struct CrtGlweTraceKey<T: FheUint> {
    metadata: AutomorphismKeyMetadata<T>,
    auto_keys: Vec<CrtGlweAutoKeyData<T>>,
}

impl<T: FheUint> CrtGlweTraceKey<T> {
    /// Generates the automorphism keys required by the trace.
    ///
    /// # Panics
    /// Panics if secret layouts or ordered moduli do not match the domain.
    ///
    /// # Correctness
    /// Both secret representations must describe the same key, with the DCRT
    /// secret using the domain table's NTT representation.
    #[must_use]
    pub fn new<M, Table, R>(
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        sk: &GlweSecretKey<T>,
        dcrt_sk: &DcrtGlweSecretKey<T>,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let log_n = domain.parameters().poly_length().log_n();
        let degrees = (1..=log_n).rev().map(|x| (1usize << x) + 1);
        let auto_keys = CrtGlweAutoKeyData::generate_key_set(domain, degrees, sk, dcrt_sk, rng);
        Self {
            metadata: AutomorphismKeyMetadata::new(domain),
            auto_keys,
        }
    }

    /// Copies the complete input before applying the ordered automorphisms.
    /// The caller maintains matching key/domain/workspace resources; scratch is
    /// overwritten and reborrowed for each step, with no ownership transfer.
    fn trace_kernel_to<M, Table>(
        &self,
        ciphertext: CrtGlweCiphertext<&[T]>,
        mut result: CrtGlweCiphertext<&mut [T]>,
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        workspace: &mut CrtGlweTraceWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let params = domain.parameters();
        let poly_length = params.poly_length().get();
        let crt_poly_length = params.rns_poly_len();
        let moduli = params.cipher_moduli();

        let (crt_glwe, auto_workspace) = workspace.as_mut();

        result.as_mut().copy_from_slice(ciphertext.as_ref());

        for auto_key in self.auto_keys.iter() {
            auto_key.automorphism_kernel(
                result.as_view(),
                crt_glwe.as_mut_view(),
                domain,
                auto_workspace,
            );
            result.add_assign(crt_glwe, poly_length, crt_poly_length, moduli);
        }
    }
}

/// CRT trace, bound to one key, numerical domain and owned scratch.
///
/// Construct once and reuse. Numerical checks do not establish secret identity
/// or agreement on the table's NTT representation; callers maintain both.
/// Ciphertexts must contain canonical residues in the bound ordered Q basis.
pub struct CrtGlweTraceEvaluator<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    key: &'a CrtGlweTraceKey<T>,
    domain: &'a DcrtGadgetDomain<'a, T, M, Table>,
    workspace: CrtGlweTraceWorkspace<T>,
}

impl<'a, T, M, Table> CrtGlweTraceEvaluator<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    /// Creates a new [`CrtGlweTraceEvaluator`] for a compatible key and domain.
    ///
    /// # Panics
    /// Panics if [`Self::try_new`] rejects the binding.
    #[must_use]
    pub fn new(key: &'a CrtGlweTraceKey<T>, domain: &'a DcrtGadgetDomain<'a, T, M, Table>) -> Self {
        Self::try_new(key, domain)
            .unwrap_or_else(|error| panic!("invalid CRT trace binding: {error}"))
    }

    /// Checks layout, ordered Q, radix and retained levels before allocating scratch.
    ///
    /// # Errors
    /// Returns [`RnsDomainError`] if the key and domain are numerically incompatible.
    pub fn try_new(
        key: &'a CrtGlweTraceKey<T>,
        domain: &'a DcrtGadgetDomain<'a, T, M, Table>,
    ) -> Result<Self, RnsDomainError<T>> {
        key.metadata.validate(domain)?;
        let workspace = CrtGlweTraceWorkspace::from_parameters(domain.parameters());
        Ok(Self {
            key,
            domain,
            workspace,
        })
    }

    /// Writes the full ring trace: `N * m[0]`, with all other coefficients zero.
    /// Input, output and scratch remain in the CRT representation.
    ///
    /// The output and reusable internal scratch are overwritten.
    ///
    /// # Correctness
    /// Both ciphertexts must match the domain's complete RNS GLWE layout,
    /// coefficient representation and the key's secret.
    pub fn trace_to<A: Data<Elem = T>, B: DataMut<Elem = T>>(
        &mut self,
        input: &CrtGlweCiphertext<A>,
        output: &mut CrtGlweCiphertext<B>,
    ) {
        let len = self.domain.parameters().rns_glwe_len();
        debug_assert_eq!(input.as_ref().len(), len);
        debug_assert_eq!(output.as_ref().len(), len);
        self.key.trace_kernel_to(
            input.as_view(),
            output.as_mut_view(),
            self.domain,
            &mut self.workspace,
        );
    }
}
