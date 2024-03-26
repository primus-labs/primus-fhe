use algebra::Polynomial;
use bfv::{BFVCiphertext, BFVPlaintext, BFVScheme, PlainField};
use criterion::{criterion_group, criterion_main, Criterion};

pub fn criterion_benchmark(c: &mut Criterion) {
    let ctx = BFVScheme::gen_context();

    c.bench_function("keygen", |b| {
        b.iter(|| {
            BFVScheme::gen_keypair(&ctx);
        });
    });

    let (sk, pk) = BFVScheme::gen_keypair(&ctx);
    let msg = Polynomial::<PlainField>::random(ctx.rlwe_dimension(), &mut *ctx.csrng_mut());
    let msg = BFVPlaintext(msg);
    c.bench_function("encrypt", |b| {
        b.iter(|| {
            BFVScheme::encrypt(&ctx, &pk, &msg);
        });
    });

    let ctxt = BFVScheme::encrypt(&ctx, &pk, &msg);

    c.bench_function("decrypt", |b| {
        b.iter(|| {
            BFVScheme::decrypt(&ctx, &sk, &ctxt);
        });
    });

    let msg2 = Polynomial::<PlainField>::random(ctx.rlwe_dimension(), &mut *ctx.csrng_mut());
    let msg2 = BFVPlaintext(msg2);

    let ctxt2 = BFVScheme::encrypt(&ctx, &pk, &msg2);

    c.bench_function("add", |b| {
        b.iter(|| {
            BFVScheme::evalute_add(&ctx, &ctxt, &ctxt2);
        });
    });

    let scalar = PlainField::random(&mut *ctx.csrng_mut());

    c.bench_function("mult_scalar", |b| {
        b.iter(|| {
            BFVScheme::evaluate_mul_scalar(&ctx, &scalar, &ctxt);
        });
    });

    let mut scalars = Vec::new();
    let mut msgs = Vec::new();
    let mut msgs_poly = Vec::new();
    for i in 0..20 {
        msgs_poly.push(Polynomial::<PlainField>::random(
            ctx.rlwe_dimension(),
            &mut *ctx.csrng_mut(),
        ));
        msgs.push(BFVPlaintext(msgs_poly[i].clone()));
        scalars.push(PlainField::random(&mut *ctx.csrng_mut()));
    }
    let ctxts: Vec<BFVCiphertext> = msgs
        .iter()
        .map(|m| BFVScheme::encrypt(&ctx, &pk, m))
        .collect();
    c.bench_function("inner-product-20", |b| {
        b.iter(|| {
            BFVScheme::evaluate_inner_product(&ctx, &ctxts, &scalars);
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
