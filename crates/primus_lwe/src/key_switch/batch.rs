use super::{LweKeySwitchingKey, accumulate_entry};
use crate::batch::{batch_iter, batch_len, check_batch};
use primus_integer::FheUint;
use primus_reduce::RingContext;

// Eight outputs amortize key reads while bounding stack state and output working set.
const TILE: usize = 8;

impl<T: FheUint> LweKeySwitchingKey<T> {
    /// Key-switches a contiguous batch in one allocation.
    ///
    /// See [`Self::key_switch_batch_to`] for layout and correctness conditions.
    /// Also panics if the output storage length overflows.
    #[must_use]
    pub fn key_switch_batch<M: RingContext<T>>(&self, input: &[T], modulus: M) -> Vec<T> {
        let count = batch_iter(input, self.input_dimension.get()).len();
        let mut output = vec![T::ZERO; batch_len(self.output_dimension.get(), count)];
        self.key_switch_batch_to(input, &mut output, modulus);
        output
    }

    /// Key-switches independent ciphertexts, overwriting the complete output.
    ///
    /// Each input chunk contains `input_dimension() + 1` coefficients; each
    /// output chunk contains `output_dimension() + 1`, with the body last.
    /// The count is inferred from `input`. Empty batches are accepted.
    /// Reuses key entries across small output tiles without allocation or
    /// caller-provided scratch. Results equal repeated [`Self::key_switch_to`].
    ///
    /// # Correctness
    ///
    /// The coefficient ranges and noise conditions of [`Self::key_switch_to`] apply.
    ///
    /// # Panics
    ///
    /// Panics before modifying output if input contains an incomplete ciphertext,
    /// the output length differs from the exact required size (or overflows), or
    /// the modulus differs from the basis modulus.
    pub fn key_switch_batch_to<M: RingContext<T>>(
        &self,
        input: &[T],
        output: &mut [T],
        modulus: M,
    ) {
        let count = batch_iter(input, self.input_dimension.get()).len();
        check_batch(output, self.output_dimension.get(), count);
        assert_eq!(
            self.basis.modulus(),
            modulus.explicit_value(),
            "LWE key-switching modulus mismatch"
        );
        if modulus.explicit_value().is_none() {
            self.key_switch_batch_kernel::<true, _>(input, output, modulus);
        } else {
            self.key_switch_batch_kernel::<false, _>(input, output, modulus);
        }
    }

    /// Lengths and modulus are validated. A tile keeps only one adjusted
    /// coefficient and its carry per ciphertext; no full decomposition is stored.
    fn key_switch_batch_kernel<const NATIVE: bool, M: RingContext<T>>(
        &self,
        input: &[T],
        output: &mut [T],
        modulus: M,
    ) {
        let input_len = self.input_dimension.ciphertext_len();
        let output_len = self.output_dimension.ciphertext_len();
        let coefficient_len = output_len * self.basis.level_count().get();
        let mut input = input;
        let mut output = output;
        while !input.is_empty() {
            let count = (input.len() / input_len).min(TILE);
            // count is bounded by the validated remaining slices, so both
            // products fit even when dimension * TILE would overflow.
            let (input_tile, input_rest) = input.split_at(count * input_len);
            let (output_tile, output_rest) = output.split_at_mut(count * output_len);
            input = input_rest;
            output = output_rest;
            for (input, output) in input_tile
                .chunks_exact(input_len)
                .zip(output_tile.chunks_exact_mut(output_len))
            {
                output[..self.output_dimension.get()].fill(T::ZERO);
                output[self.output_dimension.get()] = if NATIVE {
                    input[self.input_dimension.get()]
                } else {
                    modulus.reduce_neg(input[self.input_dimension.get()])
                };
            }
            if count == 1 {
                self.key_switch_kernel::<NATIVE, _>(
                    &input_tile[..self.input_dimension.get()],
                    output_tile,
                    modulus,
                );
                if !NATIVE {
                    modulus.reduce_neg_slice_assign(output_tile);
                }
                continue;
            }
            for (index, block) in self.data.chunks_exact(coefficient_len).enumerate() {
                let mut adjusted = [T::ZERO; TILE];
                let mut carries = [false; TILE];
                for (i, input) in input_tile.chunks_exact(input_len).enumerate() {
                    (adjusted[i], carries[i]) = self.basis.init_value_carry(input[index]);
                }
                for (decomposer, entry) in self
                    .basis
                    .decomposer_iter()
                    .zip(block.chunks_exact(output_len))
                {
                    for (i, output) in output_tile.chunks_exact_mut(output_len).enumerate() {
                        let (digit, carry) = decomposer.decompose(adjusted[i], carries[i]);
                        carries[i] = carry;
                        accumulate_entry::<NATIVE, _, _>(output, entry, digit, modulus);
                    }
                }
            }
            if !NATIVE {
                modulus.reduce_neg_slice_assign(output_tile);
            }
        }
    }
}
