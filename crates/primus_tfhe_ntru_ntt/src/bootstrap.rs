//! Shared input/BR bindings and reusable storage for serial PBS/CBS composition.
//! Standalone resources omit the ordinary PBS output-return stage.

use primus_integer::FheUint;
use primus_ntt::MonomialNttTable;
use primus_poly::Polynomial;
use primus_tfhe::TfheEvaluationError;

use crate::{
    Lwe, TfheContext,
    blind_rotation::{BlindRotationResources, blind_rotate_lookup_table_to},
    key::BlindRotationKey,
};

/// Shared NTT blind-rotation, coefficient and external-product resources.
///
/// Ordinary [`crate::Evaluator`] owns these. Standalone CBS/one-hot callers can
/// prepare them directly and borrow them for each operation. No return buffers
/// are included, and reusing these resources online requires no allocation.
/// Context, keys and the NTT table are borrowed; BR buffers are owned here.
/// Serial operations can lend one instance to each other; concurrent requests
/// need independent mutable resources and may share the immutable context/keys.
pub struct BootstrapResources<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    pub(crate) context: crate::context::EvaluationContext<'a, T, Table>,
    pub(crate) blind_rotation_key: &'a BlindRotationKey<T>,
    pub(crate) blind_rotation: BlindRotationResources<'a, T>,
}

impl<'a, T, Table> BootstrapResources<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Allocates shared BR/coefficient/external-product storage after checking the BR key.
    /// Includes classic or sparse scratch, but no return, CBS projection or MVB buffers.
    ///
    /// # Correctness
    /// The key must use this context's NTT representation and intended secrets;
    /// parameter compatibility does not establish this identity.
    pub fn try_new<LM: primus_reduce::RingContext<T>>(
        context: &'a TfheContext<T, Table, LM>,
        blind_rotation_key: &'a BlindRotationKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        if !blind_rotation_key.is_compatible(context.parameters()) {
            return Err(TfheEvaluationError::IncompatibleBlindRotationKey);
        }
        let evaluation = context.evaluation_context();
        Ok(Self {
            context: evaluation,
            blind_rotation_key,
            blind_rotation: BlindRotationResources::new(evaluation, blind_rotation_key),
        })
    }

    /// Borrows shared external-product scratch between BR/CBS operations.
    /// The next operation overwrites scratch before reading it.
    ///
    /// # Correctness
    /// Preserve its polynomial length and the called kernel's modulus, basis,
    /// transform and secret requirements. Scratch alone proves none of these.
    #[must_use]
    pub fn external_product_workspace(
        &mut self,
    ) -> &mut primus_ntru::NttNtruExternalProductWorkspace<T> {
        self.blind_rotation.rotation.external_product()
    }

    /// Rejects a different context before scratch/output writes. Prepared CBS,
    /// one-hot and MVB state depends on the context, not individual BR controls.
    /// Classic/sparse resources may be interchanged only when actual secrets
    /// match; pointer equality does not establish that secret identity.
    pub(crate) fn check_context(&self, context: crate::context::EvaluationContext<'_, T, Table>) {
        assert!(
            self.context.is_same(context),
            "bootstrap resources use a different context binding"
        );
    }

    /// Writes the coefficient-domain BR result under the accumulator secret.
    /// The owning boundary checked input/LUT geometry; no client return occurs.
    #[inline]
    pub(crate) fn blind_rotate(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &Polynomial<Vec<T>>,
        rotation_step: usize,
    ) {
        let context = self.context;
        blind_rotate_lookup_table_to(
            self.blind_rotation_key,
            input,
            lookup_table.as_view(),
            rotation_step,
            &mut self.blind_rotation,
            context,
        );
    }
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    /// Prepares shared BR/EP resources without any LWE return buffers.
    /// Inherits [`BootstrapResources::try_new`]'s key/transform requirements.
    pub fn bootstrap_resources<'a>(
        &'a self,
        key: &'a BlindRotationKey<T>,
    ) -> Result<BootstrapResources<'a, T, Table>, TfheEvaluationError> {
        BootstrapResources::try_new(self, key)
    }
}
