//! Complete LWE-to-LWE programmable-bootstrap interfaces.
//!
//! These traits describe the compiled program and external ciphertext contract.
//! Backends own blind-rotation algorithms, compatible key distributions, transform
//! representations and reusable workspace. Interleaving is a specific LUT layout;
//! other multi-value programs need interfaces matching their actual representation.
//!
//! Single LWE operands use borrowed [`Lwe`] views, independent of coefficient
//! storage. Interleaved outputs use a slice of owned [`LweCiphertext`] values.

use primus_integer::FheUint;

use crate::{InterleavedLookupTable, LookupTable, Lwe, LweCiphertext};

/// Minimal interface implemented by a complete TFHE programmable-bootstrap
/// backend.
pub trait ProgrammableBootstrap<T: FheUint> {
    /// Applies `lookup_table` to `input` and overwrites `output` with an LWE
    /// ciphertext under the backend's external client key.
    ///
    /// # Correctness
    ///
    /// The raw input must use that key and the LUT's unsigned rounded input
    /// encoding. Explicit-modulus coefficients must be canonical. Actual key,
    /// plaintext encoding and noise cannot be checked from a raw ciphertext.
    /// Front-half compilation programs `0..ceil(t/2)` or a shorter raw prefix;
    /// explicit odd full-domain compilation programs all of `0..t`. Only the
    /// compiled input domain has the requested function values. The second half
    /// of the rotation ring is always the negacyclic extension.
    /// Boolean gates deliberately use that extension and a different output scale.
    /// Input noise and modulus-switch rounding must stay within the selected LUT
    /// interval. Outputs retain the normalized scale chosen at compilation: a backend returning
    /// from accumulator modulus Q to external modulus q rescales raw values by q/Q,
    /// with rounding and return-key noise. Decode using the corresponding external
    /// codec. Raw Boolean or gadget values are not automatically re-encoded.
    ///
    /// # Panics
    ///
    /// Panics before output writes if a ciphertext dimension or the LUT's
    /// polynomial length, input encoding or accumulator modulus is incompatible.
    fn apply_lookup_table_to(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &LookupTable<T>,
        output: Lwe<&mut [T]>,
    );
}

/// Interface for evaluating an interleaved lookup table on one LWE input.
pub trait ProgrammableBootstrapInterleaved<T: FheUint> {
    /// Applies every output in `lookup_table` to `input` and overwrites
    /// `outputs` under the backend's external client key.
    ///
    /// `outputs.len()` must equal [`InterleavedLookupTable::output_count`]. Padding
    /// slots in the table do not produce additional output ciphertexts.
    /// Slice order is LUT-output order. Each ciphertext's existing coefficient
    /// buffer is overwritten in place; the buffers need not be contiguous.
    ///
    /// # Correctness
    ///
    /// Inherits [`ProgrammableBootstrap::apply_lookup_table_to`]'s key,
    /// encoding and noise requirements. The rotation resolution is `N / s`, where
    /// `s = next_power_of_two(k)` for `k` effective outputs. Account for the
    /// coarser per-coefficient modulus switching
    /// when choosing a noise budget; a valid layout alone does not ensure recovery.
    ///
    /// # Panics
    ///
    /// In addition to the single-output contract, rejects a wrong output count
    /// or any wrong output dimension before writing any output.
    fn apply_interleaved_lookup_table_to(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &InterleavedLookupTable<T>,
        outputs: &mut [LweCiphertext<T>],
    );
}

impl<T: FheUint, B: ProgrammableBootstrap<T> + ?Sized> ProgrammableBootstrap<T> for &mut B {
    #[inline]
    fn apply_lookup_table_to(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &LookupTable<T>,
        output: Lwe<&mut [T]>,
    ) {
        B::apply_lookup_table_to(self, input, lookup_table, output);
    }
}

impl<T: FheUint, B: ProgrammableBootstrapInterleaved<T> + ?Sized>
    ProgrammableBootstrapInterleaved<T> for &mut B
{
    #[inline]
    fn apply_interleaved_lookup_table_to(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &InterleavedLookupTable<T>,
        outputs: &mut [LweCiphertext<T>],
    ) {
        B::apply_interleaved_lookup_table_to(self, input, lookup_table, outputs);
    }
}
