//! Shared row-major GGSW diagonal traversal.

/// Visits the diagonal polynomial of one decomposition level in every row.
///
/// The caller maintains matching storage and layout lengths from a checked gadget
/// size. `level` must be within that size's decomposition length; the public
/// operation only diagnoses this condition with a debug assertion.
/// `poly_len`, `glwe_len` and `glev_len` count stored elements in the current
/// representation: one polynomial, one GLWE ciphertext and one complete GLev row,
/// respectively.
/// `ggsw_data` contains the entire GGSW, laid out as
/// `[row][level][component][polynomial entry]`, with as many components as rows.
/// No dimensions are inferred from the backing slice.
#[inline]
pub(crate) fn diagonal_level_mut<T>(
    ggsw_data: &mut [T],
    poly_len: usize,
    level: usize,
    glwe_len: usize,
    glev_len: usize,
) -> impl Iterator<Item = &mut [T]> {
    let level_offset = level * glwe_len;
    ggsw_data
        .chunks_exact_mut(glev_len)
        .enumerate()
        .map(move |(row, glev_data)| {
            let start = level_offset + row * poly_len;
            &mut glev_data[start..start + poly_len]
        })
}
