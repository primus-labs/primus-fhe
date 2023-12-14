use algebra::{field::NTTField, polynomial::Polynomial, ring::Ring};
use lattice::RLWE;
use num_traits::cast;

pub(crate) fn init_nand_acc<R: Ring, F: NTTField>(
    mut b: R,
    q: <R as Ring>::Inner,
    big_n: usize,
    big_q: <F as Ring>::Inner,
) -> RLWE<F> {
    let mut v = Polynomial::zero_with_coeff_count(big_n);

    let step = big_n * 2 / R::cast_into_usize(q);
    let step_r = R::cast_from_usize(step);

    let l = (cast::<u8, <R as Ring>::Inner>(3).unwrap() * q) >> 3;
    let r = (cast::<u8, <R as Ring>::Inner>(7).unwrap() * q) >> 3;

    v.iter_mut().step_by(step).for_each(|a| {
        if (l..r).contains(&b.inner()) {
            *a = F::from(big_q >> 3);
        } else {
            *a = -F::from(big_q >> 3);
        }
        b -= step_r;
    });
    RLWE::from(v)
}
