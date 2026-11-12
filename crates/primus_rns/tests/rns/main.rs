use primus_modulus::BarrettModulus;
use primus_rns::RNSBase;

mod base;
mod converter;
mod hps;
mod hybrid;

type Modulus = BarrettModulus<u64>;
type Base = RNSBase<u64, Modulus>;

fn moduli(values: &[u64]) -> Vec<Modulus> {
    values.iter().copied().map(Modulus::new).collect()
}

fn make_base(values: &[u64]) -> Base {
    Base::new(&moduli(values)).unwrap()
}

/// Modulus-major residues of signed integers, using native integer arithmetic.
fn residues(values: &[i128], moduli: &[u64]) -> Vec<u64> {
    moduli
        .iter()
        .flat_map(|&modulus| {
            values
                .iter()
                .map(move |&value| value.rem_euclid(i128::from(modulus)) as u64)
        })
        .collect()
}

fn small_inverse(value: u64, modulus: u64) -> u64 {
    let value = value % modulus;
    (1..modulus)
        .find(|&candidate| candidate * value % modulus == 1)
        .unwrap()
}

/// Unreduced CRT sums for small, nonempty modulus-major test fixtures.
/// Enumerating inverses keeps this independent of the production precomputations.
fn small_crt_lifts(input: &[u64], moduli: &[u64]) -> Vec<i128> {
    let value_count = input.len() / moduli.len();
    let product: u64 = moduli.iter().product();
    let mut lifts = vec![0; value_count];
    for (limb, &modulus) in input.chunks_exact(value_count).zip(moduli) {
        let punctured = product / modulus;
        let inverse = small_inverse(punctured, modulus);
        for (&residue, lift) in limb.iter().zip(&mut lifts) {
            *lift += i128::from((residue * inverse % modulus) * punctured);
        }
    }
    lifts
}
