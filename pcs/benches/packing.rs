use std::time::Duration;

use algebra::{
    utils::Transcript, BabyBear, BabyBearExetension, DenseMultilinearExtension, FieldUniformSampler, Field
};
use criterion::{criterion_group, criterion_main, Criterion};
use pcs::{
    multilinear::{
        BrakedownCommitmentState, BrakedownOpenProof, BrakedownPCS, BrakedownPolyCommitment,
    },
    utils::code::{ExpanderCode, ExpanderCodeSpec},
    PolynomialCommitmentScheme,
};
use rand::Rng;
use sha2::Sha256;

type FF = BabyBear;
type EF = BabyBearExetension;
type Hash = Sha256;
const BASE_FIELD_BITS: usize = 31;

/// Generate MLE of the ideneity function eq(u,x) for x \in \{0, 1\}^dim
pub fn gen_identity_evaluations<F: Field>(u: &[F]) -> DenseMultilinearExtension<F> {
    let dim = u.len();
    let mut evaluations: Vec<_> = vec![F::zero(); 1 << dim];
    evaluations[0] = F::one();
    for i in 0..dim {
        // The index represents a point in {0,1}^`num_vars` in little endian form.
        // For example, `0b1011` represents `P(1,1,0,1)`
        let u_i_rev = u[dim - i - 1];
        for b in (0..(1 << i)).rev() {
            evaluations[(b << 1) + 1] = evaluations[b] * u_i_rev;
            evaluations[b << 1] = evaluations[b] * (F::one() - u_i_rev);
        }
    }
    DenseMultilinearExtension::from_evaluations_vec(dim, evaluations)
}


pub fn criterion_benchmark(c: &mut Criterion) {
    let num_vars_poly = 15;
    let num_vars_packing =10;
    let polys: Vec<DenseMultilinearExtension<FF>> = (0..(1<<num_vars_packing)).map(|i| {
        let evaluations: Vec<FF> = rand::thread_rng()
            .sample_iter(FieldUniformSampler::new())
            .take(1 << num_vars_poly)
            .collect();
        DenseMultilinearExtension::from_evaluations_vec(num_vars_poly, evaluations)
    }).collect();

    let code_spec = ExpanderCodeSpec::new(0.1195, 0.0284, 1.9, BASE_FIELD_BITS, 10);

    let point_poly: Vec<EF> = rand::thread_rng()
        .sample_iter(FieldUniformSampler::new())
        .take(num_vars_poly)
        .collect();

    let point_index: Vec<EF> = rand::thread_rng()
        .sample_iter(FieldUniformSampler::new())
        .take(num_vars_packing)
        .collect();

    let evals: Vec<EF> = polys.iter().map(|x|x.evaluate_ext(&point_poly)).collect();

    let pp = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::setup(
        num_vars_poly,
        Some(code_spec.clone()),
    );

    
    // let mut trans = Transcript::<EF>::new();
    // let mut comms = Vec::new();
    // let mut states = Vec::new();
    // let mut proofs = Vec::new();

    // c.bench_function(&format!("num_vars_poly: {}, num_vars_packing {}, commit time (individual): ", num_vars_poly, num_vars_packing), |b| {
    //     b.iter(|| {
    //         polys.iter().for_each(|x| {
    //             let (comm, state) = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::commit(&pp, x);
    //             comms.push(comm);
    //             states.push(state);
    //         });
    //     })
    // });
   
    // c.bench_function(&format!("num_vars_poly: {}, num_vars_packing {}, opening time (individual): ", num_vars_poly, num_vars_packing), |b| {
    //     b.iter(|| {
    //     proofs = polys.iter().zip(comms.iter()).zip(states.iter()).map(|((x, comm), state)| {
    //                     BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::open(
    //                         &pp, &comm, &state, &point_poly, &mut trans,
    //                     )
    //             }).collect::<Vec<_>>();
    //     })
    // });

    // c.bench_function(
    //     &format!("num_vars_poly: {}, num_vars_packing {}, verification time (individual): ", num_vars_poly, num_vars_packing),
    //     |b| {
    //         b.iter(|| {
    //             polys.iter().zip(evals.iter()).zip(proofs.iter()).zip(comms.iter()).zip(states.iter()).for_each(|((((poly, eval), proof), comm), state)| {
    //             BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::verify(
    //                 &pp, comm, &point_poly, *eval, proof, &mut trans,
    //             );
    //         })
    //         })
    //     },
    // );

    // println!("proof size (individual): {:?} MB", proofs.iter().map(|x| x.to_bytes().unwrap().len()).sum::<usize>() >> 20);

    let pp = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::setup(
        num_vars_poly + num_vars_packing,
        Some(code_spec.clone()),
    );
    let mut trans = Transcript::<EF>::new();
    let mut comm = BrakedownPolyCommitment::default();
    let mut state = BrakedownCommitmentState::default();
    let mut proof = BrakedownOpenProof::default();

    let mut total_point = point_poly.clone();
    total_point.extend(point_index.clone());

    c.bench_function(&format!("num_vars_poly: {}, num_vars_packing {}, commit time (packing): ", num_vars_poly, num_vars_packing), |b| {
        b.iter(|| {
            let poly_packed = DenseMultilinearExtension::from_evaluations_slice(num_vars_poly + num_vars_packing, &polys.iter().flat_map(|poly| poly.iter()).cloned().collect::<Vec<_>>());
            (comm, state) =
                    BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::commit(&pp, &poly_packed)
        })
    });

    c.bench_function(&format!("num_vars_poly: {}, num_vars_packing {}, opening time (packing): ", num_vars_poly, num_vars_packing), |b| {
        b.iter(|| {
        proof = 
                BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::open(
                            &pp, &comm, &state, &total_point, &mut trans,
                        );
        })
    });

    c.bench_function(
        &format!("num_vars_poly: {}, num_vars_packing {}, verification time (packing): ", num_vars_poly, num_vars_packing),
        |b| {
            b.iter(|| {

                let random_combines = gen_identity_evaluations(&point_index);
                let eval: EF = random_combines.iter().zip(evals.iter()).map(|(index, eval)| *index * eval).fold(EF::new(0), |acc, x| acc + x);
               BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::verify(
                    &pp, &comm, &total_point, eval, &proof, &mut trans,
                );
            })
        },
    );

    println!("proof size (batching): {:?} MB", proof.to_bytes().unwrap().len() >> 20);

}

fn configure() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::new(2, 0))
        .measurement_time(Duration::new(10, 0))
        .sample_size(10)
}

criterion_group! {
    name = benches;
    config = configure();
    targets = criterion_benchmark
}

criterion_main!(benches);
