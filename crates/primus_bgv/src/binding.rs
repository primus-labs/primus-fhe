use crate::{BgvCiphertextBindingError, BgvContext};
use std::sync::Arc;

/// Local provenance attached only by this scheme's context constructors.
#[derive(Clone, Debug)]
pub(crate) struct Binding {
    context: Arc<()>,
    level: usize,
}

impl Binding {
    pub(crate) fn new(context: &BgvContext, level: usize) -> Self {
        let _ = context.rns_poly_len(level);
        Self {
            context: Arc::clone(context.identity()),
            level,
        }
    }

    pub(crate) fn check(&self, context: &BgvContext, level: usize) {
        self.validate(context, level)
            .expect("BGV ciphertext binding mismatch");
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
        self.check(context, self.level);
        self.level
    }
}

impl PartialEq for Binding {
    fn eq(&self, other: &Self) -> bool {
        self.level == other.level && Arc::ptr_eq(&self.context, &other.context)
    }
}
impl Eq for Binding {}
