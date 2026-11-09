#![cfg(feature = "batching")]

use primus_bgv::evaluation::BgvEvaluator;
use primus_bgv::{BgvClient, BgvContext, BgvParameters, ErrorDistribution, PlaintextEmbedding};
use primus_encoding::BatchingEncoder;
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

#[test]
fn plaintext_subring_keeps_the_full_secret_and_zeroes_unoccupied_slots() {
    const M: usize = 32;
    const P: u64 = 193;
    let primes = [
        1_125_899_906_248_961,
        1_125_899_906_051_329,
        1_125_899_904_322_049,
    ];
    for (n, count) in [(64, 1), (128, 3)] {
        let moduli = primes[..count]
            .iter()
            .copied()
            .map(BarrettModulus::new)
            .collect::<Vec<_>>();
        let context = BgvContext::try_new(
            BgvParameters::try_coefficients(
                PolyLength::new(n),
                BarrettModulus::new(P),
                &moduli,
                SecretKeyDistr::SparseTernary,
                ErrorDistribution::Gaussian {
                    standard_deviation: 0.849,
                },
            )
            .unwrap(),
        )
        .unwrap();
        let batching =
            BatchingEncoder::try_new(PolyLength::new(M), BarrettModulus::new(P)).unwrap();
        let mut rng = StdRng::seed_from_u64(0x09_5107 + n as u64);
        let mut client = BgvClient::generate(&context, &mut rng);
        let values = (0..17).map(|i| (11 * i + P - 7) % P).collect::<Vec<_>>();
        let offsets = vec![P - 3; 17];
        let factors = (0..M).map(|i| 1 + i as u64 % 4).collect::<Vec<_>>();
        let mut small = vec![0; M];
        let mut input = Polynomial::<Vec<u64>>::zero(n);
        let mut addend = Polynomial::<Vec<u64>>::zero(n);
        let mut multiplier = Polynomial::<Vec<u64>>::zero(n);
        batching.encode_to(&values, &mut small);
        batching.embed_to(&small, input.as_mut());
        batching.encode_to(&offsets, &mut small);
        batching.embed_to(&small, addend.as_mut());
        batching.encode_to(&factors, &mut small);
        batching.embed_to(&small, multiplier.as_mut());
        let public_key = client.public_key(&mut rng);
        let mut encryptor = context.public_key_encryptor(&public_key).unwrap();
        let mut ciphertext = context.new_ciphertext(0);
        encryptor.encrypt_centered_to(&input, &mut ciphertext, &mut rng);
        let mut evaluator = BgvEvaluator::new(&context, 0);
        evaluator.add_plain_assign(&mut ciphertext, &addend, PlaintextEmbedding::Centered);
        evaluator.mul_plain_assign(&mut ciphertext, &multiplier, PlaintextEmbedding::Centered);
        let decoded = client.decrypt_at_level(&ciphertext, 0);
        assert!(
            decoded
                .as_ref()
                .iter()
                .enumerate()
                .all(|(i, &x)| i % (n / M) == 0 || x == 0)
        );
        batching.extract_to(decoded.as_ref(), &mut small);
        let mut slots = vec![0; M];
        let mut scratch = vec![0; M];
        batching.decode_to(&small, &mut slots, &mut scratch);
        for i in 0..M {
            assert_eq!(
                slots[i],
                if i < 17 {
                    (values[i] + offsets[i]) * factors[i] % P
                } else {
                    0
                }
            );
        }
        if n == 128 {
            // p supports 2M-th roots while it has no primitive 2N-th root:
            // plaintext capacity is distinct from secret/ciphertext dimension.
            assert!(context.batching_encoder().is_err());
        }
    }
}
