use algebra::{
    modulus::BarrettModulus,
    ntt::{NttTable, NumberTheoryTransform, TableWithShoupRoot},
    reduce::{ReduceAdd, ReduceAddAssign, ReduceMul, ReduceSubAssign},
};
use rand::{distributions::Uniform, prelude::Distribution, thread_rng, Rng};

type P = u64;
const M: P = 132120577;
const N: usize = 1024;

#[test]
fn test_transform() {
    let modulus = <BarrettModulus<P>>::new(M);
    let table = <TableWithShoupRoot<P>>::new(modulus, N.trailing_zeros()).unwrap();

    let a: Vec<P> = Uniform::new(0, M)
        .sample_iter(thread_rng())
        .take(N)
        .collect();

    let mut b = a.clone();
    table.transform_slice(&mut b);
    table.inverse_transform_slice(&mut b);

    assert_eq!(a, b);
}

fn naive_mul(poly1: &[P], poly2: &[P], modulus: &BarrettModulus<P>) -> Vec<P> {
    assert_eq!(poly1.len(), poly2.len());
    let n = poly1.len();

    let mut result = vec![0; n];

    for i in 0..n {
        for j in 0..=i {
            modulus.reduce_add_assign(&mut result[i], modulus.reduce_mul(poly1[j], poly2[i - j]));
        }
    }

    // mod (x^n + 1)
    for i in n..n * 2 - 1 {
        let k = i - n;
        for j in i - n + 1..n {
            modulus.reduce_sub_assign(&mut result[k], modulus.reduce_mul(poly1[j], poly2[i - j]));
        }
    }

    result
}

#[test]
fn test_cal() {
    let mut rng = thread_rng();
    let modulus = <BarrettModulus<P>>::new(M);
    let table = <TableWithShoupRoot<P>>::new(modulus, N.trailing_zeros()).unwrap();

    let dis = Uniform::new(0, M);

    let mut a: Vec<P> = dis.sample_iter(&mut rng).take(N).collect();
    let mut b: Vec<P> = dis.sample_iter(&mut rng).take(N).collect();

    let add: Vec<P> = a
        .iter()
        .zip(b.iter())
        .map(|(&x, &y)| modulus.reduce_add(x, y))
        .collect();
    let mul = naive_mul(&a, &b, &modulus);

    table.transform_slice(&mut a);
    table.transform_slice(&mut b);

    let mut ntt_add: Vec<P> = a
        .iter()
        .zip(b.iter())
        .map(|(&x, &y)| modulus.reduce_add(x, y))
        .collect();
    let mut ntt_mul: Vec<P> = a
        .iter()
        .zip(b.iter())
        .map(|(&x, &y)| modulus.reduce_mul(x, y))
        .collect();
    table.inverse_transform_slice(&mut ntt_add);
    table.inverse_transform_slice(&mut ntt_mul);

    assert_eq!(ntt_mul, mul);
    assert_eq!(ntt_add, add);
}

#[test]
fn test_transform_monomial() {
    let mut rng = thread_rng();
    let dis = Uniform::new(0, M);

    let modulus = <BarrettModulus<P>>::new(M);
    let table = <TableWithShoupRoot<P>>::new(modulus, N.trailing_zeros()).unwrap();

    let degree: usize = rng.gen_range(0..N);
    for coeff in [1, modulus.value() - 1, dis.sample(&mut rng)] {
        let mut a = vec![0; N];
        let mut b = vec![0; N];
        a[degree] = coeff;

        table.transform_slice(&mut a);
        table.transform_monomial(coeff, degree, &mut b);

        assert_eq!(a, b);
    }
}
