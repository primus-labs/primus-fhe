use algebra::{Field, Polynomial};
use bfv::{BFVPlaintext, PlainField, ThresholdPKE};
use criterion::{criterion_group, criterion_main, Criterion};

pub fn criterion_benchmark(c: &mut Criterion) {
    type F = PlainField;

    let total_number = 3;
    let threshold_number = 2;

    let indices = [F::new(1), F::new(2), F::new(3)];

    let ctx = ThresholdPKE::gen_context(total_number, threshold_number, indices.to_vec());

    c.bench_function("tpke_keygen_(2,3)", |b| {
        b.iter(|| {
            ThresholdPKE::gen_keypair(&ctx);
        });
    });

    let (sk0, pk0) = ThresholdPKE::gen_keypair(&ctx);
    let (sk1, pk1) = ThresholdPKE::gen_keypair(&ctx);
    let (_, pk2) = ThresholdPKE::gen_keypair(&ctx);
    let (sk, pk) = ThresholdPKE::gen_keypair(&ctx);

    let pks = [pk0, pk1, pk2].to_vec();

    let msg = Polynomial::<F>::random(
        ctx.bfv_ctx().rlwe_dimension(),
        &mut *ctx.bfv_ctx().csrng_mut(),
    );
    let msg = BFVPlaintext(msg);

    c.bench_function("tpke_encrypt_(2,3)", |b| {
        b.iter(|| ThresholdPKE::encrypt(&ctx, &pks, &msg));
    });

    let ctxt = ThresholdPKE::encrypt(&ctx, &pks, &msg);

    c.bench_function("tpke_re_encrypt_(2,3)", |b| {
        b.iter(|| ThresholdPKE::re_encrypt(&ctx, &ctxt[0], &sk0, &pk));
    });

    let c0 = ThresholdPKE::re_encrypt(&ctx, &ctxt[0], &sk0, &pk);
    let c1 = ThresholdPKE::re_encrypt(&ctx, &ctxt[1], &sk1, &pk);

    let ctxts = [c0, c1].to_vec();
    let chosen_indices = [F::new(1), F::new(2)].to_vec();

    c.bench_function("tpke_combine_(2,3)", |b| {
        b.iter(|| ThresholdPKE::combine(&ctx, &ctxts, &chosen_indices));
    });

    let ctxt = ThresholdPKE::combine(&ctx, &ctxts, &chosen_indices);

    c.bench_function("tpke_decrypt_(2,3)", |b| {
        b.iter(|| ThresholdPKE::decrypt(&ctx, &sk, &ctxt));
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
