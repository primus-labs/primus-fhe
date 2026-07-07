use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, UintNttTable};
use rand::distr::{Distribution, Uniform};

type P = u64;
const M: P = 132120577;
const N: usize = 1024;

#[test]
fn root() {
    let modulus = <BarrettModulus<P>>::new(M);
    let table = <UintNttTable<P>>::new(N.trailing_zeros(), modulus).unwrap();

    let a: Vec<P> = Uniform::new(0, M)
        .unwrap()
        .sample_iter(rand::rng())
        .take(N)
        .collect();

    let mut b = a.clone();
    table.transform_slice(&mut b);
    table.inverse_transform_slice(&mut b);

    assert_eq!(a, b);
}
