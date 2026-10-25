//! Shared input/BR bindings and reusable storage for serial PBS/CBS composition.
//! Standalone resources omit the ordinary PBS output-return stage.

use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_poly::Polynomial;
use primus_tfhe::TfheEvaluationError;

use crate::{
    Lwe, TfheContext,
    blind_rotation::{BlindRotationResources, blind_rotate_lookup_table_to},
    key::BlindRotationKey,
};

/// Shared Fourier blind-rotation, coefficient, FFT and external-product resources.
///
/// Ordinary [`crate::Evaluator`] owns these. Standalone CBS/one-hot callers can
/// prepare them directly and borrow them for each operation. No return buffers
/// are included, and reusing these resources online requires no allocation.
/// Context, keys and the FFT table are borrowed; BR buffers and the FFT engine
/// are owned here.
/// Serial operations can lend one instance to each other; concurrent requests
/// need independent mutable resources and may share the immutable context/keys.
pub struct BootstrapResources<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    pub(crate) context: crate::context::EvaluationContext<'a, T, Table>,
    pub(crate) blind_rotation_key: &'a BlindRotationKey<T>,
    pub(crate) blind_rotation: BlindRotationResources<'a, T>,
    pub(crate) fft: FftEngine<'a, Table>,
}

impl<'a, T, Table> BootstrapResources<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Allocates shared BR/coefficient/FFT/external-product storage after checking the BR key.
    /// Includes classic or sparse scratch, but no return, CBS projection or MVB buffers.
    ///
    /// # Correctness
    /// The key must use this context's FFT table instance and intended secrets;
    /// parameter compatibility does not establish this identity.
    pub fn try_new<LM: primus_reduce::RingContext<T>>(
        context: &'a TfheContext<T, Table, LM>,
        blind_rotation_key: &'a BlindRotationKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        if !blind_rotation_key.is_compatible(context.parameters())
            || blind_rotation_key.precision() != context.br_precision()
        {
            return Err(TfheEvaluationError::IncompatibleBlindRotationKey);
        }
        let evaluation = context.evaluation_context();
        Ok(Self {
            context: evaluation,
            blind_rotation_key,
            blind_rotation: BlindRotationResources::new(
                evaluation,
                blind_rotation_key,
                context
                    .cbs_parameters()
                    .is_some_and(|p| p.fourier_precision() != crate::FourierCbsPrecision::ORDINARY),
            ),
            fft: context.new_fft_engine(),
        })
    }

    /// Borrows the FFT engine and external-product scratch for serial products
    /// between BR/CBS calls. Subsequent operations overwrite scratch before reading it.
    ///
    /// # Correctness
    /// Preserve the engine's table identity and both workspaces' polynomial lengths.
    /// Scratch does not establish a product's key, basis or scale compatibility.
    #[must_use]
    pub fn external_product_workspaces(
        &mut self,
    ) -> (
        &mut FftEngine<'a, Table>,
        &mut primus_ntru::FourierNtruExternalProductWorkspace<T>,
    ) {
        (
            &mut self.fft,
            self.blind_rotation.rotation.external_product(),
        )
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
            &mut self.fft,
        );
    }
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    /// Prepares shared BR/FFT/EP resources without any LWE return buffers.
    /// Inherits [`BootstrapResources::try_new`]'s key/transform requirements.
    pub fn bootstrap_resources<'a>(
        &'a self,
        key: &'a BlindRotationKey<T>,
    ) -> Result<BootstrapResources<'a, T, Table>, TfheEvaluationError> {
        BootstrapResources::try_new(self, key)
    }
}
