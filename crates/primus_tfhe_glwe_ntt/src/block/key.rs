//! Direct block controls encrypted with the existing coefficient GGSW kernel.

use primus_glwe::{
    BlockOccupancy, GgswParameters, NttGlweGadgetEncryptWorkspace, NttGlweSecretKey,
};
use primus_integer::FheUint;
use primus_lwe::LweSecretKey;
use primus_modulus::BarrettModulus;
use primus_ntt::MonomialNttTable;
use primus_tfhe_glwe::{BlockBootstrappingKeyError, BlockGlweBootstrappingKey, BlockGlweKeyLayout};
use zeroize::Zeroizing;

/// Checks an imported secret before ciphertext allocation or RNG consumption.
pub(crate) fn validate_secret<T: FheUint>(
    input: &LweSecretKey<T>,
    layout: &BlockGlweKeyLayout<T, BarrettModulus<T>>,
) -> Result<(), BlockBootstrappingKeyError> {
    // Inspect every logical coefficient, without revealing the first invalid
    // position through an early return. Public geometry was checked by layout.
    let mut invalid = false;
    let require_one = layout.occupancy() == BlockOccupancy::ExactlyOne;
    for block in input.as_ref().chunks_exact(layout.block_size()) {
        let mut occupied = false;
        for &coefficient in block {
            let selected = coefficient == T::ONE;
            invalid |= (coefficient > T::ONE) | (occupied & selected);
            occupied |= selected;
        }
        invalid |= require_one & !occupied;
    }
    if invalid {
        return Err(BlockBootstrappingKeyError::InvalidSecretCoefficients);
    }
    Ok(())
}

/// Shares the exact encryption kernel with independently imported BR secrets.
/// The owning ClientKey boundary has already checked 0/1 and occupancy per
/// logical block; the input/layout distributions and dimensions must agree.
/// Only the n logical coefficients are encrypted, excluding ring-KS zero tails.
pub(crate) fn generate_with_layout<T: FheUint, Table, R>(
    input: &LweSecretKey<T>,
    layout: BlockGlweKeyLayout<T, BarrettModulus<T>>,
    output_key: &NttGlweSecretKey<T>,
    parameters: &GgswParameters<T, BarrettModulus<T>>,
    ntt: &Table,
    rng: &mut R,
    workspace: &mut NttGlweGadgetEncryptWorkspace<T>,
) -> BlockGlweBootstrappingKey<T, BarrettModulus<T>>
where
    Table: MonomialNttTable<ValueT = T>,
    R: rand::Rng + rand::CryptoRng,
{
    let block_size = layout.block_size();
    let occupancy = layout.occupancy();
    let controls_per_block = layout.controls_per_block();
    let mut constants = Zeroizing::new(vec![T::ZERO; controls_per_block]);
    layout.generate(|range, output| {
        let block = &input.as_ref()[range];
        let mut occupied = false;
        for (constant, &coefficient) in constants[..block_size].iter_mut().zip(block) {
            *constant = coefficient;
            occupied |= coefficient == T::ONE;
        }
        if occupancy == BlockOccupancy::AtMostOne {
            constants[block_size] = if occupied { T::ZERO } else { T::ONE };
        }
        // When present, the dummy is an independent GGSW, not a subtraction
        // of the bit ciphertexts. ExactlyOne encrypts only the w constants.
        output_key.encrypt_ggsw_constant_batch_coeff_to(
            &constants, output, parameters, ntt, rng, workspace,
        );
    })
}
