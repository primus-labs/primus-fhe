use algebra::{field::NTTField, polynomial::Polynomial, ring::Ring};
use lattice::RLWE;

pub fn nand_acc<R, F>(mut b: R, nr: usize, nr2dql: usize) -> RLWE<F>
where
    R: Ring,
    F: NTTField,
{
    let mut v = Polynomial::zero_with_coeff_count(nr);

    let l = R::Q3_DIV_8.inner();
    let r = R::Q7_DIV_8.inner();

    v.iter_mut().step_by(nr2dql).for_each(|a| {
        if (l..r).contains(&b.inner()) {
            *a = F::NRG_Q_DIV_8;
        } else {
            *a = F::Q_DIV_8;
        }
        b -= R::ONE;
    });
    RLWE::new(Polynomial::zero_with_coeff_count(nr), v)
}
