//! Input layout and output gadget parameters for GLWE key switching.

use primus_integer::FheUint;
use primus_lattice::{GadgetSize, GlweDimension, GlweSize, GlweSizeError};
use primus_reduce::RingContext;
use primus_shape::PolyLength;

use super::GlevParameters;

/// Parameters for switching a GLWE ciphertext from an input secret key to an
/// output secret key.
///
/// Each input secret polynomial is encrypted as one GLev ciphertext under the
/// output key. Consequently, the output GLWE layout, encryption noise and
/// decomposition basis are all described by [`GlevParameters`].
#[derive(Clone)]
pub struct GlweKeySwitchingParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    input_size: GlweSize,
    output: GlevParameters<T, M>,
}

impl<T, M> GlweKeySwitchingParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    /// Creates GLWE key-switching parameters.
    ///
    /// `input_dimension` is the number of mask polynomials in the input GLWE
    /// key. The output dimension and polynomial length are taken from
    /// `output`.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_new`] rejects the input layout.
    #[must_use]
    #[inline]
    pub fn new(input_dimension: GlweDimension, output: GlevParameters<T, M>) -> Self {
        Self::try_new(input_dimension, output)
            .unwrap_or_else(|error| panic!("invalid GLWE key-switching input layout: {error}"))
    }

    /// Checks the input GLWE layout using the output ring's polynomial length.
    ///
    /// The output gadget layout is already checked by [`GlevParameters`].
    ///
    /// # Errors
    ///
    /// Returns [`GlweSizeError`] for an overflowing input mask, ciphertext or
    /// combined key storage length.
    pub fn try_new(
        input_dimension: GlweDimension,
        output: GlevParameters<T, M>,
    ) -> Result<Self, GlweSizeError> {
        let input_size = GlweSize::try_new(input_dimension, output.poly_length())?;
        input_dimension
            .get()
            .checked_mul(output.glev_len())
            .ok_or(GlweSizeError::LengthOverflow("GLWE key-switching key"))?;
        Ok(Self { input_size, output })
    }

    /// Returns the input GLWE dimension.
    #[must_use]
    #[inline]
    pub fn input_dimension(&self) -> GlweDimension {
        self.input_size.dimension()
    }

    /// Returns the input GLWE layout.
    #[must_use]
    #[inline]
    pub fn input_size(&self) -> GlweSize {
        self.input_size
    }

    /// Returns the output GLWE dimension.
    #[must_use]
    #[inline]
    pub fn output_dimension(&self) -> GlweDimension {
        self.output.dimension()
    }

    /// Returns the common polynomial length of the input and output keys.
    #[must_use]
    #[inline]
    pub fn poly_length(&self) -> PolyLength {
        self.output.poly_length()
    }

    /// Returns the GLev parameters used for every key-switching entry.
    #[must_use]
    #[inline]
    pub fn output(&self) -> &GlevParameters<T, M> {
        &self.output
    }

    /// Returns the output gadget layout.
    #[must_use]
    #[inline]
    pub fn output_size(&self) -> GadgetSize {
        self.output.size()
    }
}
