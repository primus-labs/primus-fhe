// use algebra::{derive::*, Field, FieldUniformSampler};
// use pcs::utils::code::{ExpanderCode, ExpanderCodeSpec, LinearCode};
// use rand::{thread_rng, Rng};

// #[derive(Field, Prime, NTT)]
// #[modulus = 63]
// pub struct FF(u64);

// fn main() {
//     let mut message: Vec<FF> = rand::thread_rng()
//         .sample_iter(FieldUniformSampler::new())
//         .take(1 << 15)
//         .collect();

//     //let code_spec: ExpanderCodeSpec = ExpanderCodeSpec::new(127, 0.1195, 0.0284, 1.9, 60, 10);
//     let code_spec: ExpanderCodeSpec = ExpanderCodeSpec::new(127, 0.2380, 0.1205, 1.720, 60, 10);

//     let code = ExpanderCode::<FF>::new(code_spec, message.len(), thread_rng());

//     message.resize(code.codeword_len(), FF::ZERO);

//     code.encode(&mut message);

//     println!("code");

//     println!("{:?}", message);
// }

fn main() {}
