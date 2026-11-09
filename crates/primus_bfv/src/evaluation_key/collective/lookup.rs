use std::{ptr, sync::Arc};

use primus_data::DataMut;
use primus_poly::DcrtPolynomial;

use crate::{
    BfvCiphertext, BfvContext,
    evaluation_key::{
        error::validate_level, material::NativeEvaluationKey, product::NativeGadgetProduct,
    },
};

use super::{BfvCollectiveError, contribution::validate_payload};

/// Independent unscaled S²-to-S key for one mixed lookup. Unlike the ordinary
/// BFV role, this key consumes raw tensors without scale-and-round.
/// Handles issued for one roster share immutable columns for the same request,
/// while each handle remains single-use.
pub struct BfvFreshLookupKey<'a> {
    pub(super) key: Arc<NativeEvaluationKey>,
    pub(super) context: &'a BfvContext,
}
/// Prepared consuming lookup owner, retaining the key and reusable scratch.
pub struct BfvFreshLookup<'a> {
    key: Arc<NativeEvaluationKey>,
    product: NativeGadgetProduct<'a>,
}
/// Checked raw mixed-tensor sum `[t0,t1,t2]` in one actual context/level.
/// It is deliberately distinct from the ordinary scaled BFV quadratic type.
pub struct BfvRawQuadraticAggregate<'a> {
    context: &'a BfvContext,
    level: usize,
    residues: Vec<u64>,
}
impl<'a> BfvRawQuadraticAggregate<'a> {
    /// Checks canonical complete raw degree-two components. The protocol must
    /// construct the intended mixed tensors and aggregate every owner once.
    pub fn try_new(
        context: &'a BfvContext,
        level: usize,
        residues: Vec<u64>,
    ) -> Result<Self, BfvCollectiveError> {
        validate_level(context, level)?;
        validate_payload(
            context.parameters().poly_length().get(),
            context.codec(level).moduli_values(),
            &residues,
            3 * context.rns_poly_len(level),
        )?;
        Ok(Self {
            context,
            level,
            residues,
        })
    }
    /// Adds another checked raw tensor sum from this actual context and level.
    pub fn add(&mut self, input: Self) -> Result<(), BfvCollectiveError> {
        if !ptr::eq(self.context, input.context) || self.level != input.level {
            return Err(BfvCollectiveError::Binding);
        }
        add_polynomials(
            self.context,
            self.level,
            &mut self.residues,
            &input.residues,
        );
        Ok(())
    }
}
impl<'a> BfvFreshLookupKey<'a> {
    /// Returns the actual numerical context owned by this fresh key's setup.
    /// This establishes neither a protocol key identity nor input provenance.
    #[must_use]
    pub fn context(&self) -> &'a BfvContext {
        self.context
    }

    /// Returns the native prefix level at which this unscaled key is consumed.
    #[must_use]
    pub fn level(&self) -> usize {
        self.key.level
    }

    /// Takes ownership of the fresh key and prepares scratch in its bound context.
    /// Finalization has already established the numerical binding; there is no
    /// external context or mutable key metadata to revalidate here.
    ///
    /// # Correctness
    /// The enclosing protocol must use independently sampled fresh setup whose
    /// errors/ephemeral do not enter raw tensor inputs, including through seeds
    /// or transcripts. Preparation does not certify this provenance or noise.
    #[must_use]
    pub fn prepare(self) -> BfvFreshLookup<'a> {
        let product = NativeGadgetProduct::try_from_validated_key(self.context, &self.key)
            .expect("validated native lookup key resources");
        BfvFreshLookup {
            key: self.key,
            product,
        }
    }
}
impl BfvFreshLookup<'_> {
    /// Consumes both this key owner and the complete raw aggregate, applying one
    /// unscaled relin and no BFV scale-and-round. Prepared arithmetic allocates
    /// nothing; binding/output errors consume the owner too.
    ///
    /// # Correctness
    /// The raw tensors use the key's actual selection secret. Selector inputs
    /// must be independent of this key's errors/ephemeral (including indirect
    /// seed/transcript dependencies). The caller separately proves total noise.
    pub fn apply_to<B: DataMut<Elem = u64>>(
        mut self,
        input: BfvRawQuadraticAggregate<'_>,
        output: &mut BfvCiphertext<B>,
    ) -> Result<(), BfvCollectiveError> {
        let context = self.product.context;
        if !ptr::eq(context, input.context) || self.key.level != input.level {
            return Err(BfvCollectiveError::Binding);
        }
        output
            .validate_binding(context, self.key.level)
            .map_err(|_| BfvCollectiveError::Binding)?;
        let len = self.product.poly_len();
        if output.as_ref().len() != 2 * len {
            return Err(BfvCollectiveError::Payload);
        }
        self.product
            .product_to(&self.key, &input.residues[2 * len..], None, output.as_mut());
        add_polynomials(
            context,
            self.key.level,
            output.as_mut(),
            &input.residues[..2 * len],
        );
        Ok(())
    }
}

fn add_polynomials(context: &BfvContext, level: usize, output: &mut [u64], input: &[u64]) {
    let len = context.rns_poly_len(level);
    let n = context.parameters().poly_length().get();
    for (output, input) in output.chunks_exact_mut(len).zip(input.chunks_exact(len)) {
        DcrtPolynomial(output).add_assign(
            &DcrtPolynomial(input),
            n,
            context.codec(level).base_q().moduli(),
        );
    }
}
