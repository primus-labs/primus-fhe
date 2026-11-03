use primus_bgv::{BgvClient, BgvContext, BgvParameters};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;
use rand::{Rng, SeedableRng, rngs::StdRng};

const Q: [u64; 3] = [1125899906248961, 1125899906051329, 1125899904322049];

fn context(n: usize, p: u64, q: &[u64]) -> BgvContext {
    BgvContext::try_with_levels(
        BgvParameters::try_with_error_distribution(
            PolyLength::new(n),
            BarrettModulus::new(p),
            &q.iter()
                .copied()
                .map(BarrettModulus::new)
                .collect::<Vec<_>>(),
            SecretKeyDistr::Ternary {
                negative_one_probability: 0.25,
                one_probability: 0.25,
            },
            ErrorDistribution::CenteredBinomial { eta: 1 },
        )
        .unwrap(),
        q.len(),
    )
    .unwrap()
}

#[test]
fn invalid_key_generation_is_rejected_before_sampling() {
    let context = context(32, 193, &Q);
    let mut rng = StdRng::seed_from_u64(0x10e0_0001);
    let client = BgvClient::generate(&context, &mut rng);
    let valid = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(10),
        level_count: None,
    };
    let invalid = [
        // Product Q supports this radix; each individual q_i does not.
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(50),
            level_count: None,
        },
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(64),
            level_count: None,
        },
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(10),
            level_count: Some(DecompositionLevelCount::new(1000)),
        },
    ];
    for config in invalid {
        let mut rng = StdRng::seed_from_u64(19);
        let mut expected = StdRng::seed_from_u64(19);
        assert!(client.relinearization_key(0, config, &mut rng).is_err());
        assert!(client.automorphism_key(0, 5, config, &mut rng).is_err());
        assert!(
            client
                .key_switching_key(&client, 0, config, &mut rng)
                .is_err()
        );
        assert_eq!(rng.next_u64(), expected.next_u64());
    }
    for level in [3, usize::MAX] {
        let mut rng = StdRng::seed_from_u64(20);
        let mut expected = StdRng::seed_from_u64(20);
        assert!(client.relinearization_key(level, valid, &mut rng).is_err());
        assert!(client.automorphism_key(level, 5, valid, &mut rng).is_err());
        assert!(
            client
                .key_switching_key(&client, level, valid, &mut rng)
                .is_err()
        );
        assert_eq!(rng.next_u64(), expected.next_u64());
    }
    for exponent in [0, 2, 64, usize::MAX] {
        let mut rng = StdRng::seed_from_u64(21);
        let mut expected = StdRng::seed_from_u64(21);
        assert!(
            client
                .automorphism_key(0, exponent, valid, &mut rng)
                .is_err()
        );
        assert_eq!(rng.next_u64(), expected.next_u64());
    }
    let incompatible = [
        self::context(32, 2, &Q),
        self::context(64, 193, &Q),
        self::context(32, 193, &[Q[2], Q[1], Q[0]]),
        self::context(32, 193, &Q[..2]),
    ];
    for other in &incompatible {
        let source = BgvClient::generate(other, &mut rng);
        let mut rng = StdRng::seed_from_u64(22);
        let mut expected = StdRng::seed_from_u64(22);
        assert!(
            client
                .key_switching_key(&source, 0, valid, &mut rng)
                .is_err()
        );
        assert_eq!(rng.next_u64(), expected.next_u64());
    }
}
