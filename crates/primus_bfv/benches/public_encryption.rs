//! Run: cargo bench -p primus_bfv --bench public_encryption
//! Smoke: cargo bench -p primus_bfv --bench public_encryption -- --test
//!
//! Each iteration encrypts once with prepared key/context/output/scratch.
//! Fixed diagnostic parameters exercise 50-bit limbs, not a security preset.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_bfv::{BfvClient, BfvContext, BfvParameters};
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

fn bench_public_encryption(c: &mut Criterion) {
    const N: usize = 1024;
    const T: u64 = 12_289;
    const SEED: u64 = 0x5353_4c45_0000_0001;
    let parameters = BfvParameters::try_new(
        PolyLength::new(N),
        BarrettModulus::new(T),
        BarrettModulus::new(2_199_023_190_017),
        &[1_125_899_906_826_241_u64, 1_125_899_906_629_633].map(BarrettModulus::new),
        SecretKeyDistr::SparseTernary,
        3.2,
    )
    .unwrap();
    let context = BfvContext::try_new(parameters).unwrap();
    let mut rng = StdRng::seed_from_u64(SEED);
    let mut client = BfvClient::generate(&context, &mut rng);
    let public = client.public_key(&mut rng);
    let mut encryptor = context.public_key_encryptor(&public).unwrap();
    let mut message = context.new_plaintext();
    for (index, coefficient) in message.as_mut().iter_mut().take(8).enumerate() {
        *coefficient = index as u64 + 1;
    }
    let mut output = context.new_ciphertext(0);

    encryptor.encrypt_to(&message, &mut output, &mut rng);
    assert_eq!(client.decrypt(&output, 0), message);

    let mut group = c.benchmark_group("public_encryption/N1024/u64/rank1");
    group.bench_function("ordinary_coefficients_to", |b| {
        b.iter(|| {
            encryptor.encrypt_to(black_box(&message), black_box(&mut output), &mut rng);
        });
    });
    group.finish();
}

criterion_group!(benches, bench_public_encryption);
criterion_main!(benches);
