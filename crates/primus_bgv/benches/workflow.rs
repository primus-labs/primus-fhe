//! One complete packed request with all resources/output prepared outside timing.
use criterion::{Criterion, criterion_group, criterion_main};
use primus_bgv::{BgvClient, BgvContext, BgvEvaluator, BgvParameters, PlaintextEmbedding};
use primus_encoding::BatchingEncoder;
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};
use std::hint::black_box;

fn bench(c: &mut Criterion) {
    const N: usize = 1024;
    const SLOTS: usize = 256;
    const P: u64 = 12289;
    // Each prime is 1 modulo both 2N and p.
    let moduli = [1_125_899_426_789_377, 1_125_899_326_117_889].map(BarrettModulus::new);
    let context = BgvContext::try_new(
        BgvParameters::try_coefficients(
            PolyLength::new(N),
            BarrettModulus::new(P),
            &moduli,
            SecretKeyDistr::SparseTernary,
            0.849,
        )
        .unwrap(),
    )
    .unwrap();
    let batching =
        BatchingEncoder::try_new(PolyLength::new(SLOTS), BarrettModulus::new(P)).unwrap();
    let values = (0..113).map(|i| 1 + i as u64 % 19).collect::<Vec<_>>();
    let offsets = vec![3; 113];
    let factors = (0..SLOTS).map(|i| 1 + i as u64 % 3).collect::<Vec<_>>();
    let mut small = vec![0; SLOTS];
    let mut scratch = vec![0; SLOTS];
    let mut slots = vec![0; SLOTS];
    let mut input = Polynomial::<Vec<u64>>::zero(N);
    let mut addend = Polynomial::<Vec<u64>>::zero(N);
    let mut multiplier = Polynomial::<Vec<u64>>::zero(N);
    let mut recovered = Polynomial::<Vec<u64>>::zero(N);
    batching.encode_to(&offsets, &mut small);
    batching.embed_to(&small, addend.as_mut());
    batching.encode_to(&factors, &mut small);
    batching.embed_to(&small, multiplier.as_mut());
    let mut rng = StdRng::seed_from_u64(0x0009_beac);
    let mut client = BgvClient::generate(&context, &mut rng);
    let key = client.public_key(&mut rng);
    let mut encryptor = context.public_key_encryptor(&key).unwrap();
    let mut evaluator = BgvEvaluator::new(&context, 0);
    let mut ciphertext = context.new_ciphertext(0);
    let mut output = context.new_ciphertext(0);
    {
        let mut request = || {
            batching.encode_to(black_box(&values), &mut small);
            batching.embed_to(&small, input.as_mut());
            encryptor.encrypt_centered_to(&input, &mut ciphertext, &mut rng);
            evaluator.add_plain_assign(&mut ciphertext, &addend, PlaintextEmbedding::Centered);
            evaluator.mul_plain_to(
                &ciphertext,
                &multiplier,
                &mut output,
                PlaintextEmbedding::Centered,
            );
            client.decrypt_to(&output, 0, &mut recovered);
            batching.extract_to(recovered.as_ref(), &mut small);
            batching.decode_to(&small, &mut slots, &mut scratch);
            black_box(&slots);
        };
        request();
        c.bench_function(
            "bgv_n1024_subring256/public_encrypt_linear_recover_slots",
            |b| b.iter(&mut request),
        );
    }
    for i in 0..SLOTS {
        assert_eq!(
            slots[i],
            if i < 113 {
                (values[i] + 3) * factors[i] % P
            } else {
                0
            }
        );
    }
}
criterion_group!(benches, bench);
criterion_main!(benches);
