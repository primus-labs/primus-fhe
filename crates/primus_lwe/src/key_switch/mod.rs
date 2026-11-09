use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_lattice::LweDimension;
use primus_lattice::lwe::Lwe;
use primus_reduce::RingContext;

mod batch;
mod parameters;

pub use parameters::LweKeySwitchingParameters;

use crate::{LweSecretKey, LweSecretKeyRef};

/// An LWE key-switching key from one secret-key vector to another.
///
/// Storage is ordered by input secret coefficient, then decomposition level;
/// every entry is an LWE encryption under the output secret key.
#[derive(Clone)]
pub struct LweKeySwitchingKey<T: FheUint> {
    data: Vec<T>,
    input_dimension: LweDimension,
    output_dimension: LweDimension,
    basis: ApproxSignedBasis<T>,
}

impl<T: FheUint> LweKeySwitchingKey<T> {
    /// Generates a key switching from `input_secret_key` to
    /// `output_secret_key`. The output key uses encoded storage so entry
    /// encryption retains the modulus backend's slice dot-product kernel.
    /// The input dimension comes from the input key; `parameters` binds the
    /// target dimension and row-noise sampler to the decomposition modulus.
    /// The generated key retains its own copy of the basis.
    ///
    /// # Correctness
    ///
    /// Encoded coefficients of either key must be canonical residues
    /// under the target ciphertext modulus in `parameters`, satisfying
    /// [`primus_reduce::ReduceDotProduct`] and [`primus_reduce::ReduceMul`].
    /// Signed input coefficients must satisfy `-q < coefficient < q` for an
    /// explicit modulus `q`; every signed value is valid for the native modulus.
    /// These coefficient ranges are not checked in release builds. The input
    /// ciphertexts must use the same modulus; this operation does not switch moduli.
    /// The input view carries no modulus metadata: callers borrowing an owning
    /// encoded input key must check its modulus before creating the view.
    ///
    /// # Panics
    ///
    /// Panics if the input key is empty, the output key dimension differs from
    /// the nonzero target parameter dimension, the output key uses another
    /// modulus, or the key storage length overflows.
    pub fn generate<R, M>(
        input_secret_key: LweSecretKeyRef<'_, T>,
        output_secret_key: &LweSecretKey<T>,
        parameters: &LweKeySwitchingParameters<T, M>,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: RingContext<T>,
    {
        let output_parameters = parameters.output();
        let basis = parameters.basis();
        output_secret_key.check_modulus(output_parameters.cipher_modulus());
        let input_dimension = LweDimension::new(input_secret_key.dimension());
        let output_dimension = output_secret_key.dimension();
        assert_eq!(
            output_dimension,
            output_parameters.dimension().get(),
            "output LWE key dimension mismatch"
        );
        let output_dimension = output_parameters.dimension();
        let output_lwe_len = output_dimension.ciphertext_len();
        let coefficient_len = output_lwe_len
            .checked_mul(basis.level_count().get())
            .expect("LWE key-switching coefficient block length overflow");
        let length = input_dimension
            .get()
            .checked_mul(coefficient_len)
            .expect("LWE key-switching key length overflow");
        let mut data = vec![T::ZERO; length];

        let modulus = output_parameters.cipher_modulus();
        let uniform = output_parameters.cipher_modulus_uniform_distr();
        let gaussian = output_parameters.noise_distribution();
        let output_key = output_secret_key.as_view();
        // Each coefficient owns a contiguous block of decomposition-level entries.
        let blocks = data.chunks_exact_mut(coefficient_len);
        let encrypt_levels = |(secret, block): (T, &mut [T])| {
            for (scalar, entry) in basis
                .scalar_iter()
                .zip(block.chunks_exact_mut(output_lwe_len))
            {
                let plaintext = modulus.reduce_mul(secret, scalar);
                output_key.encrypt_encoded_to(
                    plaintext,
                    &mut Lwe::new(entry),
                    modulus,
                    uniform,
                    gaussian,
                    rng,
                );
            }
        };
        // Select key representation once; the concrete modulus handles signed encoding.
        match input_secret_key {
            LweSecretKeyRef::Encoded(coefficients) => coefficients
                .iter()
                .copied()
                .zip(blocks)
                .for_each(encrypt_levels),
            LweSecretKeyRef::Signed(coefficients) => coefficients
                .iter()
                .copied()
                .map(|coefficient| modulus.encode_signed(coefficient))
                .zip(blocks)
                .for_each(encrypt_levels),
        }

        Self {
            data,
            input_dimension,
            output_dimension,
            basis: basis.clone(),
        }
    }

    /// Returns the input LWE dimension.
    #[must_use]
    #[inline]
    pub fn input_dimension(&self) -> LweDimension {
        self.input_dimension
    }

    /// Returns the output LWE dimension.
    #[must_use]
    #[inline]
    pub fn output_dimension(&self) -> LweDimension {
        self.output_dimension
    }

    /// Returns the key-switch decomposition basis.
    #[inline]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        &self.basis
    }

    /// Returns the raw key data.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.data
    }

    /// Key-switches `input`, overwriting all of `output` without allocating.
    ///
    /// # Correctness
    ///
    /// `input` must have canonical coefficients under the modulus used to
    /// generate this key. Decomposition approximates its mask coefficients;
    /// the resulting phase error includes both decomposition error weighted
    /// by the input secret and the accumulated key-entry noise. Parameters
    /// must leave sufficient decoding margin for the intended operation.
    ///
    /// # Panics
    ///
    /// Panics if either ciphertext lacks a body, its dimension differs from
    /// this key, or `modulus` differs from the basis modulus. Validating these
    /// conditions does not modify `output`.
    pub fn key_switch_to<M, A, B>(&self, input: &Lwe<A>, output: &mut Lwe<B>, modulus: M)
    where
        M: RingContext<T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let basis = &self.basis;
        let (input_mask, input_body) = input.a_b();
        let (output_mask, output_body) = output.a_b_mut();
        assert_eq!(
            input_mask.len(),
            self.input_dimension.get(),
            "input LWE ciphertext dimension mismatch"
        );
        assert_eq!(
            output_mask.len(),
            self.output_dimension.get(),
            "output LWE ciphertext dimension mismatch"
        );
        assert_eq!(
            basis.modulus(),
            modulus.explicit_value(),
            "LWE key-switching modulus mismatch"
        );

        output_mask.fill(T::ZERO);
        if modulus.explicit_value().is_none() {
            // Native multiplication is cheap: accumulate (0, b) - sum(digit * entry).
            *output_body = input_body;
            self.key_switch_kernel::<true, _>(input_mask, output.as_mut(), modulus);
        } else {
            // Keep positive digit multiply-adds for explicit moduli; negating
            // every general digit costs more than one final output negation.
            *output_body = modulus.reduce_neg(input_body);
            self.key_switch_kernel::<false, _>(input_mask, output.as_mut(), modulus);
            output.neg_assign(modulus);
        }
    }

    /// Accumulates mask contributions into an initialized output. Dimensions
    /// and modulus have been checked by the public boundary.
    fn key_switch_kernel<const NATIVE: bool, M: RingContext<T>>(
        &self,
        input_mask: &[T],
        output: &mut [T],
        modulus: M,
    ) {
        let output_lwe_len = self.output_dimension.ciphertext_len();
        let coefficient_len = output_lwe_len * self.basis.level_count().get();
        for (&coefficient, block) in input_mask
            .iter()
            .zip(self.data.chunks_exact(coefficient_len))
        {
            let (adjusted, mut carry) = self.basis.init_value_carry(coefficient);
            for (decomposer, entry) in self
                .basis
                .decomposer_iter()
                .zip(block.chunks_exact(output_lwe_len))
            {
                let (digit, next_carry) = decomposer.decompose(adjusted, carry);
                carry = next_carry;
                accumulate_entry::<NATIVE, _, _>(output, entry, digit, modulus);
            }
        }
    }

    /// Key-switches `input` into a newly allocated ciphertext.
    ///
    /// The correctness and panic conditions of [`Self::key_switch_to`] apply;
    /// the output dimension is determined by this key.
    pub fn key_switch<M, A>(&self, input: &Lwe<A>, modulus: M) -> Lwe<Vec<T>>
    where
        M: RingContext<T>,
        A: Data<Elem = T>,
    {
        let mut output = Lwe::zero(self.output_dimension().get());
        self.key_switch_to(input, &mut output, modulus);
        output
    }
}

/// Accumulates one key entry into a validated output. Native kernels subtract
/// digit * entry directly. Explicit-modulus kernels accumulate its positive
/// contribution and negate the complete output afterwards; this retains cheap
/// additions/subtractions for small digits without negating general digits.
#[inline]
fn accumulate_entry<const NATIVE: bool, T: FheUint, M: RingContext<T>>(
    output: &mut [T],
    entry: &[T],
    digit: T,
    modulus: M,
) {
    if digit.is_zero() {
        return;
    }
    if NATIVE {
        modulus.reduce_add_mul_scalar_slice_assign(output, entry, modulus.reduce_neg(digit));
    } else if digit == T::ONE {
        modulus.reduce_add_slice_assign(output, entry);
    } else if digit == modulus.reduce_neg(T::ONE) {
        modulus.reduce_sub_slice_assign(output, entry);
    } else if digit == T::TWO {
        modulus.reduce_add_slice_assign(output, entry);
        modulus.reduce_add_slice_assign(output, entry);
    } else if digit == modulus.reduce_neg(T::TWO) {
        modulus.reduce_sub_slice_assign(output, entry);
        modulus.reduce_sub_slice_assign(output, entry);
    } else {
        modulus.reduce_add_mul_scalar_slice_assign(output, entry, digit);
    }
}
