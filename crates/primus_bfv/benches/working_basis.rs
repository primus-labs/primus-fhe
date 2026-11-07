//! One fresh prepared request; immutable setup and buffer allocation are outside timing.
use criterion::{Criterion, criterion_group, criterion_main};
use primus_bfv::evaluation::{
    BfvLeveledMultiplication, BfvMultiplication, BfvMultiplicationBackend,
};
use primus_bfv::keys::BfvEvaluationKeyConfig;
use primus_bfv::planning::{BfvLeveledKeyBackend, BfvLeveledParameters};
use primus_bfv::{BfvCiphertext, BfvClient, BfvContext, BfvParameters};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};
use std::hint::black_box;

enum Multiplications<'a> {
    Full(Box<BfvMultiplication<'a>>),
    Planned(Vec<BfvLeveledMultiplication<'a>>),
}
impl Multiplications<'_> {
    fn apply(
        &mut self,
        a: &BfvCiphertext<Vec<u64>>,
        b: &BfvCiphertext<Vec<u64>>,
        out: &mut BfvCiphertext<Vec<u64>>,
    ) {
        match self {
            Self::Full(operation) => {
                operation.multiply_to(a, b, out);
                operation.square_assign(out);
            }
            Self::Planned(operations) => {
                operations[0].multiply_to(a, b, out);
                operations[1].square_assign(out);
            }
        }
    }
}
fn benchmark(c: &mut Criterion) {
    let q = [
        1152921422732787713,
        1152921409847689217,
        1152921396962590721,
        1152921311061934081,
    ]
    .map(BarrettModulus::new);
    for backend in [
        BfvLeveledKeyBackend::Radix16,
        BfvLeveledKeyBackend::HybridAlpha1,
    ] {
        for planned in [false, true] {
            let parameters = BfvParameters::try_coefficients(
                PolyLength::new(16384),
                BarrettModulus::new(65537),
                &q,
                SecretKeyDistr::SparseTernary,
                ErrorDistribution::CenteredBinomial { eta: 21 },
            )
            .unwrap();
            let context = BfvContext::try_with_levels(parameters, q.len()).unwrap();
            let plan = BfvLeveledParameters::try_new(&context, 2, backend).unwrap();
            let mut rng = StdRng::seed_from_u64(0x26_2026);
            let mut client = BfvClient::generate(&context, &mut rng);
            let public_key = client.public_key(&mut rng);
            let mut encryptor = context.public_key_encryptor(&public_key).unwrap();
            let keys = if planned {
                plan.steps()
                    .iter()
                    .map(|step| step.relinearization_key(&client, &mut rng).unwrap())
                    .collect::<Vec<_>>()
            } else {
                let config: BfvEvaluationKeyConfig = match backend {
                    BfvLeveledKeyBackend::Radix16 => DecompositionConfig {
                        log_basis: DecompositionBaseLog::new(16),
                        level_count: None,
                    }
                    .into(),
                    BfvLeveledKeyBackend::HybridAlpha1 => context
                        .hybrid_key_parameters(0, 4, &[1152921504606584833])
                        .unwrap()
                        .into(),
                };
                vec![client.relinearization_key(0, config, &mut rng).unwrap()]
            };
            let mut operations = if planned {
                Multiplications::Planned(
                    plan.steps()
                        .iter()
                        .zip(&keys)
                        .map(|(step, key)| step.prepare(key).unwrap())
                        .collect(),
                )
            } else {
                Multiplications::Full(Box::new(
                    BfvMultiplication::try_with_backend(
                        &context,
                        &keys[0],
                        BfvMultiplicationBackend::HpsPOverQ,
                    )
                    .unwrap(),
                ))
            };
            let mut a = Polynomial::<Vec<u64>>::zero(16384);
            let mut b = Polynomial::<Vec<u64>>::zero(16384);
            let mut recovered = Polynomial::<Vec<u64>>::zero(16384);
            let mut ca = context.new_ciphertext(0);
            let mut cb = context.new_ciphertext(0);
            let mut out = context.new_ciphertext(0);
            let name = format!(
                "bfv_q240/{backend:?}/{}/fresh_prepared_encrypt2_mul_square_decode",
                if planned {
                    "leveled_plan"
                } else {
                    "full_hps_default"
                }
            );
            c.bench_function(&name, |bencher| {
                bencher.iter(|| {
                    a.as_mut()[..2].copy_from_slice(black_box(&[2, 1]));
                    b.as_mut()[..2].copy_from_slice(black_box(&[3, 65536]));
                    encryptor.encrypt_centered_to(&a, &mut ca, &mut rng);
                    encryptor.encrypt_centered_to(&b, &mut cb, &mut rng);
                    operations.apply(&ca, &cb, &mut out);
                    client.decrypt_at_level_to(&out, 0, &mut recovered);
                    assert_eq!(&recovered.as_ref()[..5], &[36, 12, 65526, 65535, 1]);
                    assert!(recovered.as_ref()[5..].iter().all(|&x| x == 0));
                    black_box(&out);
                })
            });
        }
    }
}
criterion_group!(benches, benchmark);
criterion_main!(benches);
