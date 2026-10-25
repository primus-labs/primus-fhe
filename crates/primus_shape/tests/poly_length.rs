//! Shared FHE geometry is checked once before passing sizes across layers.

use primus_shape::{MAX_POLY_LENGTH, MIN_POLY_LENGTH, PolyLength};

#[test]
fn polynomial_length_checks_supported_geometry() {
    for log_n in MIN_POLY_LENGTH.trailing_zeros()..=MAX_POLY_LENGTH.trailing_zeros() {
        let n = 1usize << log_n;
        let length = PolyLength::try_new(n).unwrap();
        assert_eq!(length.get(), n);
        assert_eq!(length.log_n(), log_n);
        assert_eq!(length.fourier_poly_len(), n / 2);
    }
    for n in [0, 1, 2, 4, 8, 16, 31, 33, MAX_POLY_LENGTH * 2, usize::MAX] {
        assert_eq!(PolyLength::try_new(n).unwrap_err().poly_length, n);
    }
}
