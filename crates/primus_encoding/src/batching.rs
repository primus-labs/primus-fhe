use primus_modulus::BarrettModulus;
use primus_ntt::{NttError, NttTable, U64NttTable};
use primus_shape::PolyLength;

/// Exact integer slots over `F_p[Y]/(Y^n + 1)` in two rows of `n/2` slots.
///
/// For the NTT table's smallest primitive `2n`-th root `w`, row zero evaluates
/// at `w^(5^j)` and row one at `w^(-5^j)`, for `0 <= j < n/2`. A polynomial
/// automorphism `f(Y) -> f(Y^k)` therefore sends output slot `i` to the input
/// slot whose exponent is `k` times slot `i`'s exponent modulo `2n`.
///
/// This codec owns one ordinary [`U64NttTable`] and its slot permutations.
/// Prepared `*_to` operations allocate nothing; `encode` and `decode` allocate
/// their returned output and, for decoding, temporary transform scratch.
/// It changes neither a scheme's scale
/// nor a secret/ciphertext ring. In particular, embedding its `n` coefficients
/// into a larger `N`-coefficient ring does not reduce the secret dimension.
///
/// # Correctness
///
/// The plaintext modulus must be prime. Construction checks NTT availability,
/// including `p = 1 mod 2n` and `p < 2^62`, but does not prove primality, as
/// specified by [`NttTable::new`]. These are algebraic parameters, not a security
/// or noise-budget guarantee.
pub struct BatchingEncoder {
    table: U64NttTable,
    slot_to_ntt: Vec<usize>,
    odd_exponent_to_slot: Vec<usize>,
}

impl BatchingEncoder {
    /// Prepares the two-row slot layout for a supported power-of-two capacity.
    ///
    /// # Errors
    /// Returns the underlying NTT geometry, headroom or missing-root error.
    /// The prime-modulus precondition is described on [`Self`].
    pub fn try_new(
        slot_capacity: PolyLength,
        plain_modulus: BarrettModulus<u64>,
    ) -> Result<Self, NttError<u64>> {
        let table = U64NttTable::new(slot_capacity, plain_modulus)?;
        let n = slot_capacity.get();
        let mut slot_to_ntt = vec![0; n];
        let mut odd_exponent_to_slot = vec![0; n];
        let mut exponent = 1;
        for column in 0..n / 2 {
            for (row, exponent) in [(0, exponent), (1, 2 * n - exponent)] {
                let slot = row * (n / 2) + column;
                slot_to_ntt[slot] = reverse_index((exponent - 1) / 2, n);
                odd_exponent_to_slot[(exponent - 1) / 2] = slot;
            }
            exponent = exponent * 5 % (2 * n);
        }
        Ok(Self {
            table,
            slot_to_ntt,
            odd_exponent_to_slot,
        })
    }

    /// Returns `n`, the plaintext slot capacity, independently of ciphertext `N`.
    #[must_use]
    pub fn slot_capacity(&self) -> usize {
        self.table.poly_length().get()
    }

    /// Returns the plaintext modulus `p`.
    #[must_use]
    pub fn plain_modulus(&self) -> u64 {
        self.table.modulus()
    }

    /// Returns slot `i`'s odd evaluation exponent modulo `2n`.
    ///
    /// # Panics
    /// Panics if `slot >= slot_capacity()`.
    #[must_use]
    pub fn slot_exponent(&self, slot: usize) -> usize {
        2 * reverse_index(self.slot_to_ntt[slot], self.slot_capacity()) + 1
    }

    /// Allocates exactly `n` canonical coefficients for an initial slot prefix.
    ///
    /// Accepts at most `n` canonical values in `[0,p)` and pads missing slots
    /// with zero. Allocates one output vector; use [`Self::encode_to`] to reuse
    /// caller-owned storage without allocating.
    ///
    /// # Panics
    /// Panics if the slot count exceeds `n` or a slot is not canonical modulo p.
    #[must_use]
    pub fn encode(&self, slots: &[u64]) -> Vec<u64> {
        let mut coefficients = vec![0; self.slot_capacity()];
        self.encode_to(slots, &mut coefficients);
        coefficients
    }

    /// Packs an initial slot prefix into exactly `n` canonical coefficients.
    ///
    /// Missing slots are zero, including after reuse of a nonzero output. The
    /// output itself holds the inverse-transform input, so no scratch is needed.
    ///
    /// # Panics
    /// Panics before writing if the slot count exceeds `n`, the coefficient
    /// count differs from `n`, or any input slot is not canonical modulo `p`.
    pub fn encode_to(&self, slots: &[u64], coefficients: &mut [u64]) {
        let n = self.slot_capacity();
        assert!(slots.len() <= n, "too many plaintext slots");
        assert_eq!(
            coefficients.len(),
            n,
            "batching coefficient length mismatch"
        );
        self.assert_canonical(slots);
        coefficients.fill(0);
        for (&value, &index) in slots.iter().zip(&self.slot_to_ntt) {
            coefficients[index] = value;
        }
        self.table.inverse_transform_slice(coefficients);
    }

    /// Allocates all `n` ordered slots from exactly `n` canonical coefficients.
    ///
    /// Coefficients remain unchanged. Allocates one result vector and one
    /// temporary `n`-entry transform buffer, which is released before returning.
    /// Use [`Self::decode_to`] with caller-owned output and scratch to allocate
    /// nothing during decoding.
    ///
    /// # Panics
    /// Panics if the coefficient count differs from `n` or any coefficient is
    /// not canonical modulo p.
    #[must_use]
    pub fn decode(&self, coefficients: &[u64]) -> Vec<u64> {
        let mut slots = vec![0; self.slot_capacity()];
        let mut scratch = vec![0; self.slot_capacity()];
        self.decode_to(coefficients, &mut slots, &mut scratch);
        slots
    }

    /// Decodes exactly `n` canonical coefficients into all `n` ordered slots.
    ///
    /// Uses exactly `n` caller-owned scratch entries and overwrites every output
    /// and scratch entry. Coefficients remain unchanged.
    ///
    /// # Panics
    /// Panics before writing if any slice has a length other than `n` or any
    /// coefficient lies outside `[0,p)`.
    pub fn decode_to(&self, coefficients: &[u64], slots: &mut [u64], scratch: &mut [u64]) {
        let n = self.slot_capacity();
        assert_eq!(
            coefficients.len(),
            n,
            "batching coefficient length mismatch"
        );
        assert_eq!(slots.len(), n, "batching slot length mismatch");
        assert_eq!(scratch.len(), n, "batching scratch length mismatch");
        self.assert_canonical(coefficients);
        scratch.copy_from_slice(coefficients);
        self.table.transform_slice(scratch);
        for (value, &index) in slots.iter_mut().zip(&self.slot_to_ntt) {
            *value = scratch[index];
        }
    }

    /// Returns `5^steps mod 2n`, rotating each row left by `steps` positions.
    ///
    /// Steps may be negative and are normalized modulo the row length. This is
    /// a plaintext automorphism exponent, not a ciphertext rotation or its key.
    #[must_use]
    pub fn rotation_exponent(&self, steps: isize) -> usize {
        let mut power = steps.rem_euclid((self.slot_capacity() / 2) as isize) as usize;
        let modulus = (2 * self.slot_capacity()) as u64;
        let mut result = 1;
        let mut base = 5;
        while power != 0 {
            if power & 1 != 0 {
                result = result * base % modulus;
            }
            base = base * base % modulus;
            power >>= 1;
        }
        result as usize
    }

    /// Returns `-1 mod 2n`, swapping the two rows without reversing either row.
    #[must_use]
    pub fn row_swap_exponent(&self) -> usize {
        2 * self.slot_capacity() - 1
    }

    /// Applies the slot permutation of `f(Y) -> f(Y^exponent)`.
    ///
    /// The odd exponent is normalized modulo `2n`. Output slot `i` is the
    /// original slot at exponent `exponent * slot_exponent(i) mod 2n`.
    ///
    /// # Panics
    /// Panics before writing unless both slices have length `n`, the exponent
    /// is odd, and every input slot is canonical modulo `p`.
    pub fn automorphism_slots_to(&self, slots: &[u64], exponent: usize, output: &mut [u64]) {
        let n = self.slot_capacity();
        assert_eq!(slots.len(), n, "batching slot length mismatch");
        assert_eq!(output.len(), n, "batching slot output length mismatch");
        assert!(
            exponent & 1 == 1,
            "batching automorphism exponent must be odd"
        );
        self.assert_canonical(slots);
        // 2n is a power of two, so the low bits of the wrapping product suffice.
        let mask = 2 * n - 1;
        for (slot, value) in output.iter_mut().enumerate() {
            let mapped_exponent = self.slot_exponent(slot).wrapping_mul(exponent) & mask;
            *value = slots[self.odd_exponent_to_slot[(mapped_exponent - 1) / 2]];
        }
    }

    /// Embeds `f(Y)` into `f(X^(N/n))` with a complete zero-padded output.
    ///
    /// Input contains exactly `n` plaintext coefficients; output length `N`
    /// must be a power of two at least `n`. No key, ciphertext or secret is
    /// resized. The map preserves addition and negacyclic multiplication.
    ///
    /// # Panics
    /// Panics before writing on invalid lengths or noncanonical coefficients.
    pub fn embed_to(&self, coefficients: &[u64], output: &mut [u64]) {
        let n = self.slot_capacity();
        assert_eq!(
            coefficients.len(),
            n,
            "batching coefficient length mismatch"
        );
        let stride = self.embedding_stride(output.len());
        self.assert_canonical(coefficients);
        output.fill(0);
        for (value, &coefficient) in output.iter_mut().step_by(stride).zip(coefficients) {
            *value = coefficient;
        }
    }

    /// Extracts the coefficients of a polynomial in the embedded subring.
    ///
    /// Input length `N` must be a power of two at least `n`; output length is
    /// exactly `n`. Every input coefficient outside multiples of `N/n` must be
    /// zero. This checks plaintext subring membership after scheme decoding;
    /// applying it to a noisy ciphertext phase is not valid.
    ///
    /// # Panics
    /// Panics before writing on invalid lengths, noncanonical coefficients or
    /// nonzero coefficients outside the embedded subring.
    pub fn extract_to(&self, coefficients: &[u64], output: &mut [u64]) {
        assert_eq!(
            output.len(),
            self.slot_capacity(),
            "batching coefficient output length mismatch"
        );
        let stride = self.embedding_stride(coefficients.len());
        // Both ring lengths are powers of two, so the stride is as well.
        let stride_mask = stride - 1;
        self.assert_canonical(coefficients);
        assert!(
            coefficients
                .iter()
                .enumerate()
                .all(|(i, &value)| i & stride_mask == 0 || value == 0),
            "plaintext is outside the embedded subring"
        );
        for (value, &coefficient) in output.iter_mut().zip(coefficients.iter().step_by(stride)) {
            *value = coefficient;
        }
    }

    fn embedding_stride(&self, output_length: usize) -> usize {
        assert!(
            output_length >= self.slot_capacity() && output_length.is_power_of_two(),
            "embedding ring length must be a power of two at least the slot capacity"
        );
        output_length / self.slot_capacity()
    }

    fn assert_canonical(&self, values: &[u64]) {
        assert!(
            values.iter().all(|&value| value < self.plain_modulus()),
            "plaintext values must be canonical modulo p"
        );
    }
}

fn reverse_index(index: usize, n: usize) -> usize {
    index.reverse_bits() >> (usize::BITS - n.trailing_zeros())
}
