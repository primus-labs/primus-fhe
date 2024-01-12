use algebra::{NTTField, Ring};

/// Performs dot product for two slices
#[inline]
pub fn dot_product<R: Ring>(u: &[R], v: &[R]) -> R {
    debug_assert_eq!(u.len(), v.len());
    u.iter().zip(v).fold(R::ZERO, |acc, (&x, &y)| acc + x * y)
}

/// Performs enrty-wise add_mul operation.
#[inline]
pub(crate) fn ntt_add_mul_assign<
    'a,
    F: NTTField + 'a,
    I: IntoIterator<Item = &'a mut F>,
    J: IntoIterator<Item = &'a F>,
    K: IntoIterator<Item = F>,
>(
    x: I,
    y: J,
    z: K,
) {
    x.into_iter()
        .zip(y)
        .zip(z)
        .for_each(|((a, &b), c)| a.add_mul_assign(b, c));
}

/// Performs enrty-wise add_mul operation.
#[inline]
pub(crate) fn ntt_add_mul_assign_ref<
    'a,
    F: NTTField + 'a,
    I: IntoIterator<Item = &'a mut F>,
    J: IntoIterator<Item = &'a F>,
    K: IntoIterator<Item = &'a F>,
>(
    x: I,
    y: J,
    z: K,
) {
    x.into_iter()
        .zip(y)
        .zip(z)
        .for_each(|((a, &b), &c)| a.add_mul_assign(b, c));
}
