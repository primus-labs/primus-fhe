use itertools::izip;
use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_lattice::ggsw::DcrtGgsw;
use primus_ntt::NttTable;
use primus_reduce::FieldContext;
use primus_rns::Residues;

use super::{DcrtGlwePublicKeyWorkspace, encryption::PublicEncryptionResources};
use crate::CrtGlevParameters;

/// Prepared public monomial GGSW encryption with reusable ephemeral storage.
///
/// Construct with [`super::DcrtGlwePublicKey::try_bind_gadget`]. Each row/level
/// samples fresh randomness while reusing one scratch allocation. Inputs and
/// key material must agree on secret identity and NTT conventions.
pub struct DcrtGgswEncryptor<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    pub(super) resources: PublicEncryptionResources<'a, T, M, Table>,
    pub(super) parameters: &'a CrtGlevParameters<T, M>,
    pub(super) workspace: DcrtGlwePublicKeyWorkspace<T>,
}

impl<T, M, Table> DcrtGgswEncryptor<'_, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    /// Returns the retained scratch geometry and erasure contract.
    #[must_use]
    pub fn workspace(&self) -> &DcrtGlwePublicKeyWorkspace<T> {
        &self.workspace
    }

    /// Borrows scratch for explicit erasure without releasing its allocation.
    pub fn workspace_mut(&mut self) -> &mut DcrtGlwePublicKeyWorkspace<T> {
        &mut self.workspace
    }

    /// Encrypts coeff*X^degree, allocating only the complete GGSW result.
    ///
    /// # Panics
    /// Inherits [`Self::encrypt_monomial_ggsw_to`]'s coefficient count, degree
    /// and workspace shape checks.
    #[must_use]
    pub fn encrypt_monomial_ggsw<R>(
        &mut self,
        coeff_residues: &Residues<impl Data<Elem = T>>,
        degree: usize,
        rng: &mut R,
    ) -> DcrtGgsw<Vec<T>>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let mut output = DcrtGgsw::zero(self.parameters.rns_ggsw_len());
        self.encrypt_monomial_ggsw_to(coeff_residues, degree, &mut output, rng);
        output
    }

    /// Encrypts coeff*X^degree into the complete GGSW output without allocating.
    ///
    /// The coefficient has one canonical residue per ordered modulus. Gadget
    /// weights are injected into the selected row component before its one NTT;
    /// no BFV message scaling is applied. Output and ephemeral scratch are
    /// overwritten and need no clearing before reuse.
    ///
    /// # Correctness
    /// Coefficient residues, key and table must use the same ordered basis and
    /// NTT representation. These checks do not establish a noise/security bound.
    ///
    /// # Panics
    /// Panics before writes/sampling for an incorrect coefficient/output count,
    /// degree outside 0..N, or incompatible workspace. RNG/transform panics may
    /// leave partial output and scratch.
    pub fn encrypt_monomial_ggsw_to<R, A>(
        &mut self,
        coeff_residues: &Residues<impl Data<Elem = T>>,
        degree: usize,
        output: &mut DcrtGgsw<A>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        A: DataMut<Elem = T>,
    {
        let parameters = self.parameters;
        let size = self.resources.size();
        assert_eq!(
            coeff_residues.len(),
            size.moduli_count(),
            "GGSW coefficient count mismatch"
        );
        assert!(
            degree < size.poly_length().get(),
            "GGSW monomial degree must be below N"
        );
        assert_eq!(
            output.as_ref().len(),
            parameters.rns_ggsw_len(),
            "GGSW output length mismatch"
        );
        self.workspace.assert_size(size);
        for (row, mut glev) in output
            .iter_dcrt_glev_mut(parameters.rns_glev_len())
            .enumerate()
        {
            for (glwe, weights) in glev
                .iter_dcrt_glwe_mut(size.rns_glwe_len())
                .zip(parameters.scalar_residue_iter())
            {
                self.resources.encrypt_to(
                    glwe,
                    self.workspace.as_mut_slice(),
                    rng,
                    |component, polynomial| {
                        if component == row {
                            for (limb, &coefficient, &weight, modulus) in izip!(
                                polynomial.iter_each_modulus_mut(size.poly_length().get()),
                                coeff_residues.iter(),
                                weights.iter(),
                                parameters.cipher_moduli(),
                            ) {
                                limb[degree] =
                                    modulus.reduce_mul_add(coefficient, weight, limb[degree]);
                            }
                        }
                    },
                );
            }
        }
    }
}
