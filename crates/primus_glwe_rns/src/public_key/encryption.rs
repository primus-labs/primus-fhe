use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_lattice::{RnsGlweSize, glwe::DcrtGlwe};
use primus_ntt::{DcrtTable, NttTable};
use primus_poly::{CrtPolynomial, DcrtPolynomial};
use primus_reduce::FieldContext;
use primus_rns::RNSBase;

use super::{DcrtGlwePublicKey, DcrtGlwePublicKeyWorkspace};
use crate::parameter::validate_dcrt_table;
use crate::{CrtGlweEncryptionParameters, RnsDomainError};

/// Resources numerically checked once before an encryptor allocates its scratch.
pub(super) struct PublicEncryptionResources<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    key: &'a DcrtGlwePublicKey<T>,
    parameters: &'a CrtGlweEncryptionParameters<T>,
    rns_base: &'a RNSBase<T, M>,
    table: &'a DcrtTable<Table>,
}

impl<'a, T, M, Table> PublicEncryptionResources<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    pub(super) fn try_new(
        key: &'a DcrtGlwePublicKey<T>,
        parameters: &'a CrtGlweEncryptionParameters<T>,
        rns_base: &'a RNSBase<T, M>,
        table: &'a DcrtTable<Table>,
    ) -> Result<Self, RnsDomainError<T>> {
        parameters.validate_base(rns_base)?;
        validate_dcrt_table(parameters.size().poly_length(), rns_base.moduli(), table)?;
        key.validate_parameters(parameters.size(), rns_base.moduli())?;
        Ok(Self {
            key,
            parameters,
            rns_base,
            table,
        })
    }

    pub(super) fn size(&self) -> RnsGlweSize {
        self.parameters.size()
    }

    /// The public operation validates complete input/output/workspace layouts.
    /// Each GLWE gets a fresh ephemeral polynomial; injection precedes the one
    /// transform per noisy component. No temporary vector or transform is added.
    pub(super) fn encrypt_to<R>(
        &self,
        mut output: DcrtGlwe<&mut [T]>,
        ephemeral: &mut [T],
        rng: &mut R,
        mut inject_component: impl FnMut(usize, &mut CrtPolynomial<&mut [T]>),
    ) where
        R: rand::Rng + rand::CryptoRng,
    {
        let size = self.size();
        let n = size.poly_length().get();
        let rns_poly_len = size.rns_poly_len();
        primus_distr::sample_crt_sparse_ternary_values_to(
            ephemeral,
            n,
            self.parameters.cipher_moduli_minus_one(),
            rng,
        );
        self.table.transform_slice(ephemeral);
        let ephemeral = DcrtPolynomial(&*ephemeral);
        for (index, (mut component, public_component)) in output
            .iter_dcrt_poly_mut(rns_poly_len)
            .zip(self.key.key.iter_dcrt_poly(rns_poly_len))
            .enumerate()
        {
            self.parameters
                .sample_noise_to(component.as_mut(), self.rns_base.moduli_values(), rng);
            inject_component(index, &mut CrtPolynomial(component.as_mut()));
            self.table.transform_slice(component.as_mut());
            component.add_mul_assign(&ephemeral, &public_component, n, self.rns_base.moduli());
        }
    }

    pub(super) fn assert_output(&self, length: usize, workspace: &DcrtGlwePublicKeyWorkspace<T>) {
        assert_eq!(
            length,
            self.size().rns_glwe_len(),
            "public GLWE output length mismatch"
        );
        workspace.assert_size(self.size());
    }
}

/// Prepared codec-free public encryption of zero or already-encoded CRT phases.
///
/// This owns only one reusable ephemeral polynomial and borrows the public key,
/// sampling state, basis and table. No scheme scaling or decoding is performed.
pub struct DcrtGlweRawPublicKeyEncryptor<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    pub(super) resources: PublicEncryptionResources<'a, T, M, Table>,
    pub(super) workspace: DcrtGlwePublicKeyWorkspace<T>,
}

impl<T, M, Table> DcrtGlweRawPublicKeyEncryptor<'_, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    /// Encrypts with a coefficient-noise injection for each GLWE component.
    ///
    /// Calls `inject_component(index, polynomial)` once for each component in
    /// mask-then-body order, immediately after its coefficient noise is sampled
    /// and before its single NTT. The body index is the GLWE dimension. This
    /// allows schemes to fuse encoding or noise scaling without another buffer
    /// or transform. A fresh ephemeral is sampled first; output and retained
    /// scratch are overwritten. The kernel allocates nothing; callback costs
    /// belong to its caller.
    ///
    /// # Correctness
    /// Each callback must leave canonical coefficients in the bound ordered Q
    /// basis. The caller owns message/noise semantics and their recovery bound;
    /// the primitive retains phase `b - sum(a_i*s_i)`.
    ///
    /// # Panics
    /// Validates complete output and workspace layouts before sampling or
    /// callbacks. An RNG, callback or transform panic may leave partial buffers.
    pub fn encrypt_with_components_to<R, A>(
        &mut self,
        output: &mut DcrtGlwe<A>,
        rng: &mut R,
        inject_component: impl FnMut(usize, &mut CrtPolynomial<&mut [T]>),
    ) where
        R: rand::Rng + rand::CryptoRng,
        A: DataMut<Elem = T>,
    {
        self.resources
            .assert_output(output.as_ref().len(), &self.workspace);
        self.resources.encrypt_to(
            output.as_mut_view(),
            self.workspace.as_mut_slice(),
            rng,
            inject_component,
        );
    }

    /// Returns the retained scratch geometry and erasure contract.
    #[must_use]
    pub fn workspace(&self) -> &DcrtGlwePublicKeyWorkspace<T> {
        &self.workspace
    }

    /// Borrows scratch for explicit erasure without releasing its allocation.
    pub fn workspace_mut(&mut self) -> &mut DcrtGlwePublicKeyWorkspace<T> {
        &mut self.workspace
    }

    /// Encrypts zero into the complete DCRT output without allocating.
    ///
    /// # Panics
    /// Panics before writes/sampling on an incorrect output or workspace shape.
    /// RNG/transform panics can leave partial output and scratch.
    pub fn encrypt_zeros_to<R, A>(&mut self, output: &mut DcrtGlwe<A>, rng: &mut R)
    where
        R: rand::Rng + rand::CryptoRng,
        A: DataMut<Elem = T>,
    {
        self.resources
            .assert_output(output.as_ref().len(), &self.workspace);
        self.resources.encrypt_to(
            output.as_mut_view(),
            self.workspace.as_mut_slice(),
            rng,
            |_, _| {},
        );
    }

    /// Encrypts an already-encoded coefficient-domain CRT phase without allocation.
    ///
    /// Adds the canonical input directly to coefficient noise before the body's
    /// single NTT. No BFV scale or gadget weights are applied; output is overwritten.
    ///
    /// # Correctness
    /// Input residues and order must match the bound basis and intended encoded
    /// phase. Public-key/noise contributions require their own recovery bound.
    ///
    /// # Panics
    /// Panics before writes/sampling for incorrect input/output/workspace shape.
    /// RNG/transform panics can leave partial output and scratch.
    pub fn encrypt_encoded_crt_to<R, A, B>(
        &mut self,
        message: &CrtPolynomial<A>,
        output: &mut DcrtGlwe<B>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let size = self.resources.size();
        assert_eq!(
            message.as_ref().len(),
            size.rns_poly_len(),
            "encoded CRT phase length mismatch"
        );
        self.resources
            .assert_output(output.as_ref().len(), &self.workspace);
        self.resources.encrypt_to(
            output.as_mut_view(),
            self.workspace.as_mut_slice(),
            rng,
            |index, polynomial| {
                if index == size.dimension().get() {
                    polynomial.add_assign(
                        message,
                        size.poly_length().get(),
                        self.resources.rns_base.moduli(),
                    );
                }
            },
        );
    }
}
