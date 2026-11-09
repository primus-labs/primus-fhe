use primus_fft::Complex64;
use primus_lattice::{
    ngsw::{FourierNgsw, FourierNgswIter},
    nlev::FourierNlev,
};

/// Borrowed classic NTRU blind-rotation material, unavailable for sparse keys.
///
/// The initializer encrypts one. Coordinate zero uses NLEV bit controls for
/// fused lifting; the remaining coordinates use NGSW bit controls. Binary
/// secrets have one bit per coordinate; ternary secrets have positive/negative
/// pairs, in that order. All material uses the server key's BR basis and
/// transform representation. This view borrows the key and allocates nothing.
#[derive(Clone, Copy)]
pub struct ClassicControls<'a> {
    initializer: &'a FourierNlev<Vec<Complex64>>,
    first_positive: &'a [Complex64],
    first_negative: Option<&'a [Complex64]>,
    remaining: &'a [Complex64],
}

impl<'a> ClassicControls<'a> {
    // Generated classic storage is complete and nonempty. Split its special
    // first coordinate once, before the online coordinate loop.
    pub(super) fn new(
        initializer: &'a FourierNlev<Vec<Complex64>>,
        data: &'a [Complex64],
        binary: bool,
    ) -> Self {
        let control_len = initializer.as_ref().len();
        let (first_positive, remaining) = data.split_at(control_len);
        let (first_negative, remaining) = if binary {
            (None, remaining)
        } else {
            let (negative, remaining) = remaining.split_at(control_len);
            (Some(negative), remaining)
        };
        Self {
            initializer,
            first_positive,
            first_negative,
            remaining,
        }
    }

    /// Returns the NLEV encryption of one, for lifting public polynomials.
    #[must_use]
    pub fn initializer(&self) -> FourierNlev<&'a [Complex64]> {
        self.initializer.as_view()
    }

    /// Returns whether each coordinate uses one binary control instead of a ternary pair.
    #[must_use]
    pub fn is_binary(&self) -> bool {
        self.first_negative.is_none()
    }

    /// Returns coordinate zero's positive bit and optional negative bit as NLEV views.
    #[must_use]
    pub fn first_controls(
        &self,
    ) -> (
        FourierNlev<&'a [Complex64]>,
        Option<FourierNlev<&'a [Complex64]>>,
    ) {
        (
            FourierNlev::new(self.first_positive),
            self.first_negative.map(FourierNlev::new),
        )
    }

    /// Iterates the remaining NGSW bits in coordinate order.
    /// Ternary bits alternate positive/negative; binary bits have no negative member.
    #[must_use]
    pub fn remaining_controls(&self) -> FourierNgswIter<'a> {
        FourierNgswIter::new(self.remaining, self.initializer.as_ref().len())
    }

    // The ternary BR arm already established paired storage. Semantic iterators
    // retain ciphertext boundaries while the two strides select each pair's signs.
    pub(crate) fn ternary_controls(
        &self,
    ) -> impl Iterator<Item = (FourierNgsw<&'a [Complex64]>, FourierNgsw<&'a [Complex64]>)> {
        self.remaining_controls()
            .step_by(2)
            .zip(self.remaining_controls().skip(1).step_by(2))
    }
}
