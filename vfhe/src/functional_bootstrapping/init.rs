use algebra::{field::NTTField, polynomial::Polynomial, ring::Ring};
use lattice::RLWE;
use num_traits::cast;

pub(crate) fn nand_acc<R, F>(
    mut b: R,
    ql: <R as Ring>::Inner,
    nr: usize,
    qr: <F as Ring>::Inner,
) -> RLWE<F>
where
    R: Ring,
    F: NTTField,
{
    let mut v = Polynomial::zero_with_coeff_count(nr);

    let step = (nr << 1) / R::new(ql).cast_into_usize();

    let l = (cast::<u8, <R as Ring>::Inner>(3).unwrap() * ql) >> 3;
    let r = (cast::<u8, <R as Ring>::Inner>(7).unwrap() * ql) >> 3;

    let x = F::from(qr >> 3);
    let y = -F::from(qr >> 3);

    v.iter_mut().step_by(step).for_each(|a| {
        if (l..r).contains(&b.inner()) {
            *a = y;
        } else {
            *a = x;
        }
        b -= R::one();
    });
    RLWE::from(v)
}
