//! Exact coefficient GGSW encryption for contiguous block controls.

use primus_fft::{FftTable, TorusFftValue};
use primus_glwe::{BlockOccupancy, FourierGlweEncryptor};
use primus_modulus::NativeModulus;
use primus_reduce::RingContext;
use primus_tfhe_glwe::BlockGlweKeyLayout;
use zeroize::Zeroizing;

use crate::{ClientKey, KeyGenerator, block::BlockGlweBootstrappingKey};

impl<T, Table, LM> KeyGenerator<'_, T, Table, LM>
where
    T: TorusFftValue,
    LM: RingContext<T>,
    Table: FftTable,
{
    /// Encrypts complete logical blocks after client compatibility was established
    /// by sampling or validation. Public ring-KS zero tails are not controls.
    pub(crate) fn generate_block_bootstrapping_key_with_accumulator<R>(
        &mut self,
        client: &ClientKey<T>,
        layout: BlockGlweKeyLayout<T, NativeModulus<T>>,
        encryptor: &mut FourierGlweEncryptor<'_, T>,
        rng: &mut R,
    ) -> BlockGlweBootstrappingKey<T, NativeModulus<T>>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let block_size = layout.block_size();
        let occupancy = layout.occupancy();
        let gadget = self.context.parameters().blind_rotation_params();
        let controls_per_block = layout.controls_per_block();
        let mut constants = Zeroizing::new(vec![T::ZERO; controls_per_block]);
        let input = client.small_lwe_secret_key().as_ref();
        layout.generate(|range, output| {
            let block = &input[range];
            let mut occupied = false;
            for (constant, &coefficient) in constants[..block_size].iter_mut().zip(block) {
                *constant = coefficient;
                occupied |= coefficient == T::ONE;
            }
            if occupancy == BlockOccupancy::AtMostOne {
                constants[block_size] = if occupied { T::ZERO } else { T::ONE };
            }
            // When present, the dummy has fresh row errors independent of the
            // bit controls. ExactlyOne has no extra constant or RNG draws.
            // Reuse the exact auxiliary-NTT/CRT products, then retain torus rows.
            encryptor.encrypt_ggsw_constant_batch_coeff_to(&constants, output, gadget, rng);
        })
    }
}
