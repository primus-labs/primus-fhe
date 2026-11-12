//! Exact native controls written before any online Fourier conversion.

use primus_fft::{FftTable, TorusFftValue};
use primus_lattice::nlev::Nlev;
use primus_ntru::{BlockOccupancy, FourierNtruSecretKey};
use primus_tfhe_ntru::BlockNtruKeyLayout;

use crate::{ClientKey, KeyGenerator};

impl<T, Table, LM> KeyGenerator<'_, T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    /// Writes all bits and any mode-required dummy from the accepted secret's
    /// exact inverse. Sampling or ClientKey validation established occupancy.
    /// No approximate Fourier ciphertext is converted back to coefficients.
    pub(crate) fn generate_block_blind_rotation_key_with_main<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        client: &ClientKey<T>,
        accumulator_fourier: &FourierNtruSecretKey,
        layout: BlockNtruKeyLayout<T>,
        rng: &mut R,
    ) -> crate::key::BlindRotationKey<T> {
        let parameters = self.context.parameters();
        let gadget = parameters.blind_rotation();
        let control_len = gadget.nlev_len();
        let has_dummy = layout.occupancy() == BlockOccupancy::AtMostOne;
        let secret = client.external_lwe_secret_key().as_ref();
        let controls = layout.generate(|range, output| {
            let first = range.start == 0;
            let block = &secret[range];
            let occupied = block
                .iter()
                .fold(false, |occupied, &bit| occupied | (bit == T::ONE));
            for (bit, coefficients) in block
                .iter()
                .map(|&bit| bit == T::ONE)
                .chain(has_dummy.then_some(!occupied))
                .zip(output.chunks_exact_mut(control_len))
            {
                // The first whole block is NLEV, even when all exponents vanish:
                // all bit controls (and the optional dummy) lift the public LUT.
                // Every following block instead uses NGSW.
                accumulator_fourier.encrypt_gadget_bit_coeff_to(
                    bit,
                    first,
                    Nlev::new(coefficients),
                    gadget,
                    rng,
                    &mut self.gadget,
                );
            }
        });
        crate::key::BlindRotationKey::from_block(parameters, controls, self.context.br_precision())
    }
}
