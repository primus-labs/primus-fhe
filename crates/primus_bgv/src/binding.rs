use crate::{BgvCiphertextBindingError, BgvContext};
use std::sync::Arc;

/// The correction factor and local provenance travel with the same storage owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CiphertextMetadata {
    pub(super) binding: Option<Binding>,
    pub(super) correction_factor: u64,
}

impl CiphertextMetadata {
    pub(super) fn raw() -> Self {
        Self {
            binding: None,
            correction_factor: 1,
        }
    }

    pub(super) fn bound(context: &BgvContext, level: usize) -> Self {
        Self {
            binding: Some(Binding::new(context, level)),
            ..Self::raw()
        }
    }

    pub(super) fn check_binding(&self, context: &BgvContext, level: usize) {
        self.validate_binding(context, level)
            .expect("BGV ciphertext binding mismatch");
    }

    pub(super) fn validate_binding(
        &self,
        context: &BgvContext,
        level: usize,
    ) -> Result<(), BgvCiphertextBindingError> {
        match &self.binding {
            Some(binding) => binding.validate(context, level),
            None => Ok(()),
        }
    }
}

/// Local provenance attached only by this scheme's context constructors.
#[derive(Clone, Debug)]
pub(crate) struct Binding {
    context: Arc<()>,
    level: usize,
}

impl Binding {
    // Called only after the owner has selected a prepared level.
    pub(crate) fn new(context: &BgvContext, level: usize) -> Self {
        Self {
            context: Arc::clone(context.identity()),
            level,
        }
    }

    pub(crate) fn validate(
        &self,
        context: &BgvContext,
        level: usize,
    ) -> Result<(), BgvCiphertextBindingError> {
        if !Arc::ptr_eq(&self.context, context.identity()) {
            return Err(BgvCiphertextBindingError::ContextMismatch);
        }
        if self.level != level {
            return Err(BgvCiphertextBindingError::BoundLevel {
                expected: level,
                actual: self.level,
            });
        }
        Ok(())
    }

    pub(crate) fn level(&self, context: &BgvContext) -> usize {
        self.validate(context, self.level)
            .expect("BGV ciphertext binding mismatch");
        self.level
    }
}

impl PartialEq for Binding {
    fn eq(&self, other: &Self) -> bool {
        self.level == other.level && Arc::ptr_eq(&self.context, &other.context)
    }
}
impl Eq for Binding {}
