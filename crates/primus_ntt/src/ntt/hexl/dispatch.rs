use crate::ntt::hexl::{
    internal::*,
    transform::{
        forward_transform_to_bit_reverse_avx512, inverse_transform_from_bit_reverse_avx512,
    },
};

use super::HexlNttTable;
use super::scalar::{
    forward_transform_to_bit_reverse_radix2_inplace,
    inverse_transform_from_bit_reverse_radix2_inplace,
};

/// Which direction of NTT to compute.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TransformDirection {
    /// Forward NTT: polynomial → NTT domain
    Forward,
    /// Inverse NTT: NTT domain → polynomial
    Inverse,
}

impl HexlNttTable {
    /// Unified dispatch: selects the optimal AVX512 path (IFMA → DQ → scalar)
    /// based on CPU features and modulus size.
    pub fn compute_transform(
        &self,
        operand: &mut [u64],
        input_mod_factor: u64,
        output_mod_factor: u64,
        direction: TransformDirection,
    ) {
        match direction {
            TransformDirection::Forward => {
                debug_assert_eq!(operand.len(), self.n);
                debug_assert!(
                    input_mod_factor == 1 || input_mod_factor == 2 || input_mod_factor == 4,
                    "input_mod_factor must be 1, 2 or 4; got {input_mod_factor}",
                );
                debug_assert!(
                    output_mod_factor == 1 || output_mod_factor == 4,
                    "output_mod_factor must be 1 or 4; got {output_mod_factor}",
                );

                if *super::HAS_AVX512IFMA && self.q < MAX_FWD_IFMA_MODULUS && self.n >= 16 {
                    unsafe {
                        forward_transform_to_bit_reverse_avx512::<IFMA_SHIFT_BITS>(
                            operand,
                            self.q,
                            self.avx512_root_of_unity_powers(),
                            self.avx512_precon52_root_of_unity_powers(),
                            input_mod_factor,
                            output_mod_factor,
                            0,
                            0,
                        )
                    };
                    return;
                }

                if *super::HAS_AVX512DQ && self.n >= 16 {
                    if self.q < MAX_FWD_32_MODULUS {
                        unsafe {
                            forward_transform_to_bit_reverse_avx512::<32>(
                                operand,
                                self.q,
                                self.avx512_root_of_unity_powers(),
                                self.avx512_precon32_root_of_unity_powers(),
                                input_mod_factor,
                                output_mod_factor,
                                0,
                                0,
                            )
                        };
                    } else {
                        unsafe {
                            forward_transform_to_bit_reverse_avx512::<DEFAULT_SHIFT_BITS>(
                                operand,
                                self.q,
                                self.avx512_root_of_unity_powers(),
                                self.avx512_precon64_root_of_unity_powers(),
                                input_mod_factor,
                                output_mod_factor,
                                0,
                                0,
                            )
                        };
                    }
                    return;
                }

                forward_transform_to_bit_reverse_radix2_inplace(
                    operand,
                    self.q,
                    self.root_of_unity_powers(),
                    self.precon64_root_of_unity_powers(),
                    output_mod_factor as u32,
                );
            }

            TransformDirection::Inverse => {
                debug_assert!(
                    input_mod_factor == 1 || input_mod_factor == 2,
                    "input_mod_factor must be 1 or 2; got {input_mod_factor}",
                );
                debug_assert!(
                    output_mod_factor == 1 || output_mod_factor == 2,
                    "output_mod_factor must be 1 or 2; got {output_mod_factor}",
                );

                if *super::HAS_AVX512IFMA && self.q < MAX_INV_IFMA_MODULUS && self.n >= 16 {
                    unsafe {
                        inverse_transform_from_bit_reverse_avx512::<IFMA_SHIFT_BITS>(
                            operand,
                            self.q,
                            self.inv_n,
                            self.inv_root_of_unity_powers(),
                            self.precon52_inv_root_of_unity_powers(),
                            input_mod_factor,
                            output_mod_factor,
                            0,
                            0,
                        );
                    }
                    return;
                }

                if *super::HAS_AVX512DQ && self.n >= 16 {
                    if self.q < MAX_INV_32_MODULUS {
                        unsafe {
                            inverse_transform_from_bit_reverse_avx512::<32>(
                                operand,
                                self.q,
                                self.inv_n,
                                self.inv_root_of_unity_powers(),
                                self.precon32_inv_root_of_unity_powers(),
                                input_mod_factor,
                                output_mod_factor,
                                0,
                                0,
                            );
                        }
                    } else {
                        unsafe {
                            inverse_transform_from_bit_reverse_avx512::<DEFAULT_SHIFT_BITS>(
                                operand,
                                self.q,
                                self.inv_n,
                                self.inv_root_of_unity_powers(),
                                self.precon64_inv_root_of_unity_powers(),
                                input_mod_factor,
                                output_mod_factor,
                                0,
                                0,
                            );
                        }
                    }
                    return;
                }

                inverse_transform_from_bit_reverse_radix2_inplace(
                    operand,
                    self.q,
                    self.inv_n,
                    self.inv_root_of_unity_powers(),
                    self.precon64_inv_root_of_unity_powers(),
                    output_mod_factor as u32,
                );
            }
        }
    }

    /// Computes the forward NTT. Results are bit-reversed.
    #[inline]
    pub fn compute_forward(
        &self,
        operand: &mut [u64],
        input_mod_factor: u64,
        output_mod_factor: u64,
    ) {
        self.compute_transform(
            operand,
            input_mod_factor,
            output_mod_factor,
            TransformDirection::Forward,
        );
    }

    /// Computes the inverse NTT.
    #[inline]
    pub fn compute_inverse(
        &self,
        operand: &mut [u64],
        input_mod_factor: u64,
        output_mod_factor: u64,
    ) {
        self.compute_transform(
            operand,
            input_mod_factor,
            output_mod_factor,
            TransformDirection::Inverse,
        );
    }
}
