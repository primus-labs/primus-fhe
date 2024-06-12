use algebra::{derive::*, DenseMultilinearExtension, Field, FieldUniformSampler};
use criterion::{criterion_group, criterion_main, Criterion};
use pcs::{
    multilinear::brakedown::{prover::PcsProver, verifier::PcsVerifier, BrakedownProtocol},
    utils::code::{LinearCode, ExpanderCodeSpec, ExpanderCode},
};
use rand::{thread_rng, Rng};
use std::mem;


#[derive(Field, Prime, NTT)]
#[modulus = 63]
pub struct FF(u64);

fn main() {

    let mut message: Vec<FF> = rand::thread_rng()
        .sample_iter(FieldUniformSampler::new())
        .take(1 << 12)
        .collect();

    //let code_spec: ExpanderCodeSpec = ExpanderCodeSpec::new(127, 0.1195, 0.0284, 1.9, 60, 10);
    let code_spec: ExpanderCodeSpec = ExpanderCodeSpec::new(127, 0.2380, 0.1205, 1.720, 60, 10);

    println!("{:?}\n\n", code_spec);
    
    let code  = ExpanderCode::<FF>::new(code_spec, message.len(),thread_rng());

    //println!("{:?}", message);


    message.resize(code.codeword_len(),FF::ZERO);

    code.encode(&mut message);

    println!("code");

    
    //println!("{:?}", message);

}