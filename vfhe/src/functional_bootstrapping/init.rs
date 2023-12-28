use algebra::{field::NTTField, polynomial::Polynomial, ring::Ring};
use lattice::RLWE;
use num_traits::cast;

pub fn nand_acc<R, F>(
    mut b: R,
    ql: <R as Ring>::Inner,
    nr: usize,
    qr: <F as Ring>::Inner,
    nr2dql: usize,
) -> RLWE<F>
where
    R: Ring,
    F: NTTField,
{
    let mut v = Polynomial::zero_with_coeff_count(nr);

    let l = (cast::<u8, <R as Ring>::Inner>(3).unwrap() * ql) >> 3;
    let r = (cast::<u8, <R as Ring>::Inner>(7).unwrap() * ql) >> 3;

    let x = F::from(qr >> 3);
    let y = -x;
    let one = R::one();

    v.iter_mut().step_by(nr2dql).for_each(|a| {
        if (l..r).contains(&b.inner()) {
            *a = y;
        } else {
            *a = x;
        }
        b -= one;
    });
    RLWE::new(Polynomial::zero_with_coeff_count(nr), v)
}
