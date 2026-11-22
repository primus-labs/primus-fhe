//! Exact coefficient controls encrypted using the accepted accumulator transform.

use num_traits::{ConstOne, ConstZero};
use primus_integer::FheUint;
use primus_lattice::nlev::NttNlev;
use primus_ntru::{BlockOccupancy, NttNtruSecretKey};
use primus_ntt::MonomialNttTable;
use primus_tfhe_ntru::BlockNtruKeyLayout;
use zeroize::Zeroizing;

use crate::{ClientKey, KeyGenerator};

impl<T, Table, LM> KeyGenerator<'_, T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    /// Encrypts every bit and any required dummy using the accepted f transform
    /// and inverse. Sampling or the ClientKey boundary established 0/1 and the
    /// declared occupancy; no secret-dependent control is omitted or rescanned.
    pub(crate) fn generate_block_blind_rotation_key_with_main<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        client: &ClientKey<T>,
        accumulator_ntt: &NttNtruSecretKey<T>,
        layout: BlockNtruKeyLayout<T>,
        rng: &mut R,
    ) -> crate::key::BlindRotationKey<T> {
        let parameters = self.context.parameters();
        let gadget = parameters.blind_rotation();
        let control_len = gadget.nlev_len();
        let ntt = self.context.table();
        let has_dummy = layout.occupancy() == BlockOccupancy::AtMostOne;
        let block_size = layout.block_size();
        let controls_per_block = block_size + usize::from(has_dummy);
        let mut constants = Zeroizing::new(vec![T::SignedInteger::ZERO; controls_per_block]);
        let secret = client.external_lwe_secret_key().as_ref();
        let controls = layout.generate(|range, output| {
            let first = range.start == 0;
            let block = &secret[range];
            let mut occupied = false;
            for (&bit, constant) in block.iter().zip(&mut constants[..block_size]) {
                let selected = bit == T::ONE;
                *constant = if selected {
                    T::SignedInteger::ONE
                } else {
                    T::SignedInteger::ZERO
                };
                occupied |= selected;
            }
            if has_dummy {
                constants[block_size] = if occupied {
                    T::SignedInteger::ZERO
                } else {
                    T::SignedInteger::ONE
                };
            }
            // The first *whole block* uses NLEV, with a dummy only for AtMostOne.
            // Its public-LUT lift is compulsory even when every exponent is zero.
            // Every later block has NGSW controls, with the same product layout.
            if first {
                for (&bit, row) in constants.iter().zip(output.chunks_exact_mut(control_len)) {
                    accumulator_ntt.encrypt_nlev_constant_to(
                        if bit == T::SignedInteger::ONE {
                            T::ONE
                        } else {
                            T::ZERO
                        },
                        &mut NttNlev::new(row),
                        gadget,
                        ntt,
                        rng,
                        &mut self.gadget,
                    );
                }
            } else {
                accumulator_ntt
                    .encrypt_ngsw_signed_constant_batch_to(&constants, output, gadget, ntt, rng);
            }
            // Group aggregation consumes canonical coefficient controls. Keep
            // only this representation instead of a second transformed BSK.
            for polynomial in output.chunks_exact_mut(parameters.poly_length().get()) {
                ntt.inverse_transform_slice(polynomial);
            }
        });
        crate::key::BlindRotationKey::from_block(parameters, controls)
    }
}
