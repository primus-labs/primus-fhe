use algebra::{field::NTTField, polynomial::Polynomial, ring::Ring};
use lattice::RLWE;
use num_traits::cast;

pub(crate) fn nand_acc<R: Ring, F: NTTField>(
    mut b: R,
    q: <R as Ring>::Inner,
    l: usize,
    p: <F as Ring>::Inner,
) -> RLWE<F> {
    let mut v = Polynomial::zero_with_coeff_count(l);

    let step = l * 2 / R::new(q).cast_into_usize();
    let step_r = R::cast_from_usize(step);

    let l = (cast::<u8, <R as Ring>::Inner>(3).unwrap() * q) >> 3;
    let r = (cast::<u8, <R as Ring>::Inner>(7).unwrap() * q) >> 3;

    let x = F::from(p >> 3);
    let y = -F::from(p >> 3);

    v.iter_mut().step_by(step).for_each(|a| {
        if (l..r).contains(&b.inner()) {
            *a = x;
        } else {
            *a = y;
        }
        b -= step_r;
    });
    RLWE::from(v)
}
