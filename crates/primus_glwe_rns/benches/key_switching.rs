use primus_shape::PolyLength;
// cargo bench -p primus_glwe_rns --bench key_switching

use primus_decompose::DecompositionBaseLog;
use primus_lattice::GlweDimension;
use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use primus_glwe_rns::{
    CrtGlevParameters, CrtGlweParameters, DcrtGadgetDomain, DcrtGlweCiphertext,
    DcrtGlweDecryptWorkspace, DcrtGlweKeySwitchEvaluator, DcrtGlweKeySwitchingKey,
    DcrtGlweSecretKey, GlweSecretKey, HybridRnsGlweKeySwitchEvaluator,
    HybridRnsGlweKeySwitchingKey, HybridRnsKeySwitchDomain, SecretKeyDistr,
};
use primus_lattice::glwe::DcrtGlwe;
use primus_modulus::BarrettModulus;
use primus_ntt::U64DcrtTable;
use primus_poly::Polynomial;
use primus_rns::HybridRNS;
use rand::{SeedableRng, rngs::StdRng};

fn bench_key_switching(c: &mut Criterion) {
    type Value = u64;

    const DIMENSION: usize = 1;
    const PLAINTEXT_MODULUS: Value = 2;
    const GAMMA: Value = 2_305_843_009_213_554_689;
    const Q_VALUES: [Value; 2] = [1_125_899_906_826_241, 1_125_899_906_629_633];
    const P_VALUES: [Value; 2] = [1_125_899_906_031_617, 1_125_899_904_679_937];
    const DECOMPOSITION_BASE_LOG: u32 = 20;
    const HYBRID_CASES: [(&str, usize); 2] = [("grouped", 1), ("singleton", 2)];

    let mod_t = BarrettModulus::new(PLAINTEXT_MODULUS);
    let mod_gamma = BarrettModulus::new(GAMMA);
    let q_moduli = Q_VALUES.map(BarrettModulus::new);
    let p_moduli = P_VALUES.map(BarrettModulus::new);
    let qp_moduli: Vec<_> = q_moduli.iter().chain(p_moduli.iter()).copied().collect();

    let mut rng = StdRng::seed_from_u64(0xdec0_005e);
    let mut group = c.benchmark_group("key_switching");
    group.sample_size(10);

    for log_n in [10u32, 11, 12] {
        let poly_length = PolyLength::new(1usize << log_n);
        let q_table = U64DcrtTable::new(poly_length, &q_moduli).unwrap();
        let qp_table = U64DcrtTable::new(poly_length, &qp_moduli).unwrap();

        let glwe_params = CrtGlweParameters::new(
            GlweDimension::new(DIMENSION),
            poly_length,
            mod_t,
            mod_gamma,
            &q_moduli,
            SecretKeyDistr::SparseTernary,
            3.20,
        );
        let input_sk = GlweSecretKey::generate(
            glwe_params.size().glwe_size(),
            glwe_params.secret_key_sampler(),
            &mut rng,
        );
        let input_dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&input_sk, &q_table);
        let output_sk = GlweSecretKey::generate(
            glwe_params.size().glwe_size(),
            glwe_params.secret_key_sampler(),
            &mut rng,
        );
        let output_dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&output_sk, &q_table);

        let glev_params = CrtGlevParameters::with_glwe_params(
            &glwe_params,
            DecompositionBaseLog::new(DECOMPOSITION_BASE_LOG),
            None,
        );
        let dcrt_domain = DcrtGadgetDomain::try_new(&glev_params, &q_table).unwrap();

        // Key generation is intentionally outside the timed region.
        let crt_ksk = DcrtGlweKeySwitchingKey::generate(
            &input_sk,
            glwe_params.encryption_parameters(),
            &output_dcrt_sk,
            &dcrt_domain,
            &mut rng,
        );
        let rns_glwe_len = glwe_params.rns_glwe_len();
        let input: Polynomial<Vec<Value>> = Polynomial::random(poly_length.get(), mod_t, &mut rng);
        let mut input_ciphertext: DcrtGlwe<Vec<Value>> = DcrtGlweCiphertext::zero(rns_glwe_len);
        let input_dcrt_sk_context = input_dcrt_sk.try_bind(&glwe_params, &q_table).unwrap();
        input_dcrt_sk_context.encrypt_to(&input, &mut input_ciphertext, &mut rng);
        let input_coeff = input_ciphertext.clone().into_coeff_form(&q_table);

        let mut crt_output: DcrtGlwe<Vec<Value>> = DcrtGlweCiphertext::zero(rns_glwe_len);
        let mut crt_evaluator = DcrtGlweKeySwitchEvaluator::new(&crt_ksk, &dcrt_domain);
        // Validate the CRT path before measuring it.
        crt_evaluator.key_switch_to(&input_coeff, &mut crt_output);
        let mut decrypt_workspace = DcrtGlweDecryptWorkspace::new(glwe_params.size());
        let output_dcrt_sk_context = output_dcrt_sk.try_bind(&glwe_params, &q_table).unwrap();
        assert_eq!(
            output_dcrt_sk_context.decrypt(&crt_output, &mut decrypt_workspace),
            input,
        );
        group.throughput(Throughput::Elements(poly_length.get() as u64));
        let n_label = format!("N={}", poly_length.get());

        group.bench_function(BenchmarkId::new("CRT-bit-decomposition", &n_label), |b| {
            b.iter(|| {
                crt_evaluator.key_switch_to(black_box(&input_coeff), black_box(&mut crt_output));
            });
        });

        for (partition_label, decomposition_count) in HYBRID_CASES {
            let hybrid_rns = HybridRNS::new(&q_moduli, &p_moduli, decomposition_count).unwrap();
            let hybrid_domain = HybridRnsKeySwitchDomain::try_new(&hybrid_rns, &qp_table).unwrap();
            let hybrid_ksk = HybridRnsGlweKeySwitchingKey::generate(
                &input_sk,
                glwe_params.encryption_parameters(),
                &output_sk,
                &hybrid_domain,
                &mut rng,
            );
            let mut hybrid_output: DcrtGlwe<Vec<Value>> = DcrtGlweCiphertext::zero(rns_glwe_len);
            let mut hybrid_evaluator =
                HybridRnsGlweKeySwitchEvaluator::new(&hybrid_ksk, &hybrid_domain);

            hybrid_evaluator.key_switch_to(&input_ciphertext, &mut hybrid_output);
            assert_eq!(
                output_dcrt_sk_context.decrypt(&hybrid_output, &mut decrypt_workspace),
                input,
            );

            group.bench_function(
                BenchmarkId::new(format!("Hybrid-RNS-{partition_label}"), &n_label),
                |b| {
                    b.iter(|| {
                        hybrid_evaluator.key_switch_to(
                            black_box(&input_ciphertext),
                            black_box(&mut hybrid_output),
                        );
                    });
                },
            );
        }
    }

    group.finish();
}

criterion_group!(benches, bench_key_switching);
criterion_main!(benches);
