//! Modulus switching to rotation exponents for LUT compilation and blind rotation.
//!
//! Compilation and execution use the same rounding and rotation-step rules.
//! These operations act on public ciphertext coefficients; the blind-rotation
//! key and algorithm determine how encrypted secret coefficients select rotations.
//!
//! For canonical `x` modulo `q`, rotation quantization is
//! `R(x, q, L) = floor((x * L + floor(q / 2)) / q) mod L`.
//! Ties round upward, including the wrap from `L` to zero; `NativeModulus<T>` uses
//! `q = 2^T::BITS`. With rotation step `s`, let `R_s(x) = s * R(x, q, 2N/s)`.
//! Backends rotate the LUT by
//! `-R_s(b) + sum(R_s(a[i]) * secret[i])`, quantizing each LWE coefficient
//! separately. Quantizing the decrypted phase once is not equivalent.

use primus_integer::FheUint;
use primus_modulus::PowOf2Modulus;
use primus_reduce::{ModulusSwitch, PrepareModulusSwitch};

/// Prepared modulus switching from input coefficients to rotation exponents.
///
/// Combines [`ModulusSwitch`] with a power-of-two rotation step and `usize`
/// outputs. Ordinary PBS and factorized MVB use step one. Interleaved PBS uses
/// the padded output count; CBS and one-hot use their padded gadget width.
/// LUT compilation uses the same rounding to place the encoded output intervals.
#[derive(Clone, Copy, Debug)]
pub struct RotationModulusSwitch<T: FheUint> {
    switch: ModulusSwitch<T>,
    input_modulus: Option<T>,
    two_n: usize,
    rotation_step: usize,
}

impl<T: FheUint> RotationModulusSwitch<T> {
    /// Creates a [`RotationModulusSwitch`] for
    /// `rotation_step * R(value, q, two_n/rotation_step)`.
    /// Rounding in the smaller domain preserves interleaved LUT residue classes.
    /// ManyLUT execution uses `two_n = 2N` and the LUT's padded output count `s`
    /// as the step. Compilation uses `two_n = 2N/s` and step one to obtain
    /// centers in per-output coefficient coordinates.
    ///
    /// # Panics
    /// Panics unless `two_n >= 2` and `rotation_step` are powers of two,
    /// `rotation_step <= two_n/2`, and `two_n` is representable by `T`.
    #[must_use]
    pub fn new<M>(modulus: M, two_n: usize, rotation_step: usize) -> Self
    where
        M: PrepareModulusSwitch<ValueT = T>,
    {
        assert!(
            two_n >= 2 && two_n.is_power_of_two(),
            "invalid rotation domain"
        );
        assert!(
            rotation_step.is_power_of_two() && rotation_step <= two_n / 2,
            "invalid rotation step"
        );
        let rotation_domain =
            T::try_from(two_n).expect("rotation domain must fit the input coefficient type");
        let target = rotation_domain >> rotation_step.trailing_zeros();
        let switch = modulus.prepare_switch_to(PowOf2Modulus::new(target));
        Self {
            switch,
            input_modulus: modulus.explicit_value(),
            two_n,
            rotation_step,
        }
    }

    /// Prepares another LUT spacing in the same q and 2N domains.
    /// Changing the target before rounding is essential: rounding at step one
    /// and rounding that result again is not equivalent at half-grid boundaries.
    /// Returns the existing preparation when the spacing is unchanged.
    ///
    /// # Panics
    /// Panics unless `rotation_step` is a power of two no larger than N.
    #[must_use]
    pub fn with_step(self, rotation_step: usize) -> Self {
        if rotation_step == self.rotation_step {
            return self;
        }
        assert!(
            rotation_step.is_power_of_two() && rotation_step <= self.two_n / 2,
            "invalid rotation step"
        );
        let target = PowOf2Modulus::new(T::try_from(self.two_n / rotation_step).unwrap());
        let switch = match self.input_modulus {
            Some(q) => ModulusSwitch::new(primus_modulus::UintModulus::new(q), target),
            None => ModulusSwitch::new(primus_modulus::NativeModulus::<T>::new(), target),
        };
        Self {
            switch,
            rotation_step,
            ..self
        }
    }

    /// Whether this quantizer was prepared for the given input modulus and
    /// rotation domain. `None` denotes the native modulus `2^T::BITS`.
    /// Operation binding must additionally match [`Self::rotation_step`] to
    /// the LUT's slot layout; matching domains alone does not establish that.
    #[must_use]
    pub fn is_compatible(&self, input_modulus: Option<T>, two_n: usize) -> bool {
        self.input_modulus == input_modulus && self.two_n == two_n
    }

    /// Returns the spacing of output rotation exponents, fixed at construction.
    #[must_use]
    pub fn rotation_step(&self) -> usize {
        self.rotation_step
    }

    /// Modulus-switches one canonical input coefficient to a rotation exponent
    /// in `[0,two_n)`, aligned to `rotation_step`.
    ///
    /// # Correctness
    /// `value` must be canonical under the input modulus used at construction.
    #[must_use]
    #[inline]
    pub fn exponent(&self, value: T) -> usize {
        let exponent: usize = self.switch.switch(value).try_into().unwrap();
        exponent * self.rotation_step
    }

    /// Modulus-switches coefficients into an equally sized slice of rotation exponents.
    /// Fuses conversion to `usize`, rotation-step scaling and output writes with
    /// the prepared switch's batch operation, without intermediate allocation.
    ///
    /// # Correctness
    /// Every input coefficient must satisfy [`Self::exponent`]'s source range.
    ///
    /// # Panics
    /// Panics if the slices differ in length, before writing any output.
    #[inline]
    pub fn exponent_slice_to(&self, input: &[T], output: &mut [usize]) {
        assert_eq!(
            input.len(),
            output.len(),
            "rotation exponent slice length mismatch"
        );
        self.switch
            .switch_map(input.iter().copied().zip(output), |value, out| {
                let exponent: usize = value.try_into().unwrap();
                *out = exponent * self.rotation_step;
            });
    }
}
