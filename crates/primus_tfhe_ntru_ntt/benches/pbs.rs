//! cargo bench -p primus_tfhe_ntru_ntt --bench pbs
//! Parameters and comparison limits: guides/development/testing.md#tfhe-benchmarks
//! One iteration is one server request. Setup and correctness checks are untimed.

use criterion::{Criterion, Throughput};
use primus_integer::FheUint;
use primus_lwe::LweDimension;
use primus_modulus::PowOf2Modulus;
use primus_ntru::SecretKeyDistr;
use primus_ntt::{MonomialNttTable, U32NttTable, U64NttTable};
use primus_shape::PolyLength;
use primus_tfhe::DecompositionBaseLog;
use primus_tfhe_ntru_ntt::{
    BlindRotationMethod, DecompositionConfig, GadgetEncryptionConfig, LweConfig, ModulusConfig,
    PbsConfig, PbsMessageConfig, TfheContext, experimental,
};
use rand::{SeedableRng, rngs::StdRng};
use std::hint::black_box;

/// The u32 fixture follows the documented dense profile; never truncate a u64 config.
fn dense_u32() -> PbsConfig<u32, PowOf2Modulus<u32>> {
    let full = |log| DecompositionConfig {
        log_basis: DecompositionBaseLog::new(log),
        level_count: None,
    };
    PbsConfig {
        external_lwe: LweConfig {
            dimension: LweDimension::new(866),
            cipher_modulus: ModulusConfig::Explicit(1 << 24),
            secret_key_distr: SecretKeyDistr::UniformBinary,
            noise_standard_deviation: 2.046_151_696_979_124e-6 * f64::from(1 << 24),
        },
        ring_modulus: ModulusConfig::Explicit(132_120_577),
        bsk_poly_length: PolyLength::new(2048),
        bsk_secret_distr: SecretKeyDistr::SparseTernary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: full(2),
            noise_standard_deviation: 0.7,
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: full(3),
            noise_standard_deviation: 3.2,
        },
        method: BlindRotationMethod::Classic,
        messages: PbsMessageConfig::new(32),
    }
}

/// Prepare one complete PBS at its actual word, modulus and return domain.
fn measure<Word: FheUint, Table: MonomialNttTable<ValueT = Word>>(
    c: &mut Criterion,
    engine: &str,
    case: &str,
    config: PbsConfig<Word, PowOf2Modulus<Word>>,
) {
    let context = TfheContext::<Word, Table, _>::try_from_pbs_config(config).unwrap();
    // Client: reset both seeds per case so fixed classic/sparse use matching inputs.
    let mut key_rng = StdRng::seed_from_u64(42);
    let (client, server) = context.try_generate_keys(&mut key_rng).unwrap();
    let secret = client.external_lwe_secret_key();
    let encryptor = context.encryptor(secret).unwrap();
    let decryptor = context.pbs_decryptor(secret).unwrap();
    let mut rng = StdRng::seed_from_u64(4242);
    let mut input = context.allocate_lwe_ciphertext();

    // Server: allocate/compile before Criterion's closure, then check the returned LWE.
    let table = context
        .pbs_lookup_table_compiler()
        .unwrap()
        .compile_fn(|x| Word::as_from((3 * x + 1) % 16))
        .unwrap();
    let mut evaluator = context.evaluator(&server).unwrap();
    let mut output = context.allocate_lwe_ciphertext();
    for message in [0, 7] {
        encryptor
            .encrypt_padded_to(Word::as_from(message), input.as_mut_view(), &mut rng)
            .unwrap();
        evaluator.apply_lookup_table_to(input.as_view(), &table, output.as_mut_view());
        assert_eq!(
            decryptor.decrypt(output.as_view()).unwrap(),
            Word::as_from((3 * message + 1) % 16)
        );
    }
    let mut group = c.benchmark_group(format!("pbs/ntru/{engine}"));
    group.throughput(Throughput::Elements(1)); // Complete requests, not output count.
    group.bench_function(case, |b| {
        b.iter(|| {
            evaluator.apply_lookup_table_to(
                black_box(input.as_view()),
                black_box(&table),
                output.as_mut_view(),
            );
            black_box(output.as_view());
        })
    });
    group.finish();
    assert_eq!(
        decryptor.decrypt(output.as_view()).unwrap(),
        Word::as_from(6)
    );
}

fn benchmarks(c: &mut Criterion) {
    // Only the algorithm changes in this fixed-weight comparison; dense uses a different profile.
    let mut fixed = experimental::SPARSE_PBS_U64;
    fixed.method = BlindRotationMethod::Classic;
    measure::<u32, U32NttTable>(c, "ntt", "classic_dense/u32", dense_u32());
    measure::<u64, U64NttTable>(c, "ntt", "classic_dense/u64", experimental::CLASSIC_PBS_U64);
    measure::<u64, U64NttTable>(c, "ntt", "classic_fixed/u64", fixed);
    measure::<u64, U64NttTable>(c, "ntt", "sparse_fixed/u64", experimental::SPARSE_PBS_U64);
}

criterion::criterion_group! {
    name = benches;
    config = criterion::Criterion::default().sample_size(20)
        .warm_up_time(std::time::Duration::from_secs(1))
        .measurement_time(std::time::Duration::from_secs(3));
    targets = benchmarks
}
criterion::criterion_main!(benches);
