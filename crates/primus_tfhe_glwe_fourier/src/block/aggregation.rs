//! Coefficient aggregation and Fourier scratch for direct block blind rotation.

use primus_fft::{Complex64, TorusFftValue};
use primus_lattice::{
    ggsw::{FourierGgsw, Ggsw},
    glwe::TorusGlwe,
    workspace::FourierGlweExternalProductWorkspace,
};
use primus_modulus::NativeModulus;
use primus_poly::Polynomial;

use super::BlockGlweBootstrappingKey;
/// Single-input scratch reused across all blocks, including both occupancy modes.
pub(crate) struct ControlAggregationWorkspace<T: TorusFftValue> {
    pub(crate) input_exponents: Vec<usize>,
    pub(crate) aggregate: Ggsw<Vec<T>>,
    pub(crate) transformed: FourierGgsw<Vec<Complex64>>,
    pub(crate) scratch: TorusGlwe<Vec<T>>,
    pub(crate) external_product: FourierGlweExternalProductWorkspace<T>,
}

impl<T: TorusFftValue> ControlAggregationWorkspace<T> {
    pub(crate) fn new(key: &BlockGlweBootstrappingKey<T, NativeModulus<T>>) -> Self {
        let size = key.size();
        Self {
            input_exponents: vec![0; key.input_dimension().get()],
            aggregate: Ggsw::zero(size.ggsw_len()),
            transformed: FourierGgsw::zero(size.fourier_ggsw_len()),
            scratch: TorusGlwe::zero(size.glwe_len()),
            external_product: FourierGlweExternalProductWorkspace::new(size),
        }
    }

    pub(crate) fn with_external_product<R>(
        &mut self,
        size: primus_lattice::GadgetSize,
        operation: impl FnOnce(&mut FourierGlweExternalProductWorkspace<T>) -> R,
    ) -> R {
        self.external_product.with_rebound(size, operation)
    }
}

/// Adds all rotated bit controls to an aggregate already initialized to zero
/// or its independently encrypted dummy. Complete coefficient layouts are established
/// by the owning key; every control contributes, including zero exponents.
/// Pairing preserves the native wrapping order while loading and storing each
/// aggregate coefficient only once per pair.
#[inline]
pub(crate) fn aggregate_controls_assign<T: TorusFftValue>(
    mut exponents: impl ExactSizeIterator<Item = usize>,
    selections: &[T],
    aggregate: &mut Ggsw<Vec<T>>,
    poly_length: usize,
    modulus: NativeModulus<T>,
) {
    let ggsw_len = aggregate.as_ref().len();
    debug_assert_eq!(selections.len(), exponents.len() * ggsw_len);
    let mut selection_pairs = selections.chunks_exact(2 * ggsw_len);
    for pair in selection_pairs.by_ref() {
        let (a, b) = pair.split_at(ggsw_len);
        aggregate.add_mul_monomial_pair_assign(
            &Ggsw::new(a),
            exponents.next().expect("complete control pair"),
            &Ggsw::new(b),
            exponents.next().expect("complete control pair"),
            poly_length,
            modulus,
        );
    }
    if let Some(exponent) = exponents.next() {
        for (acc, source) in aggregate
            .as_mut()
            .chunks_exact_mut(poly_length)
            .zip(selection_pairs.remainder().chunks_exact(poly_length))
        {
            Polynomial(acc).add_mul_monomial_assign(&Polynomial(source), exponent, modulus);
        }
    }
}
