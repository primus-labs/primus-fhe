//! Representation-independent preparation and batch validation for expansion.

use primus_factor::ShoupFactor;
use primus_integer::FheUint;
use primus_reduce::FieldContext;
use primus_rns::ResidueFactors;

use crate::CrtGlevParameters;

/// Prepares 2^-depth in every ordered limb, including depth zero.
/// One inverse of two per modulus suffices for the entire dyadic tree. CRT
/// decomposition and a fresh big-integer temporary per depth are unnecessary.
pub(crate) fn normalization_factors<T: FheUint, M: FieldContext<T>>(
    parameters: &CrtGlevParameters<T, M>,
) -> Vec<ResidueFactors<Vec<ShoupFactor<T>>>> {
    let mut levels: Vec<_> = (0..=parameters.poly_length().log_n())
        .map(|_| ResidueFactors(Vec::with_capacity(parameters.base_q().moduli_count())))
        .collect();
    for modulus in parameters.cipher_moduli() {
        let inverse_two = modulus.reduce_inv(T::ONE + T::ONE);
        let mut inverse_count = T::ONE;
        for factors in &mut levels {
            factors
                .0
                .push(ShoupFactor::new(inverse_count, modulus.value()));
            inverse_count = modulus.reduce_mul(inverse_count, inverse_two);
        }
    }
    levels
}

/// Validates the whole batch before normalization writes its first output.
/// Counts have distinct public contracts and are checked by each entry point.
pub(crate) fn assert_expansion_layout<T>(
    input_length: usize,
    output: &[impl AsRef<[T]>],
    expected_length: usize,
) {
    assert_eq!(
        input_length, expected_length,
        "expansion input layout mismatch"
    );
    assert!(
        output
            .iter()
            .all(|ciphertext| ciphertext.as_ref().len() == expected_length),
        "expansion output layout mismatch",
    );
}
