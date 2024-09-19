use algebra::{BabyBear, BabyBearExetension, DenseMultilinearExtension, Field};
use num_traits::Zero;
use pcs::utils::code::{ExpanderCode, ExpanderCodeSpec};
use rand::prelude::*;
use sha2::Sha256;
use std::rc::Rc;
use zkp::piop::{LookupInstance, LookupSnarks};

type FF = BabyBear;
type EF = BabyBearExetension;
type Hash = Sha256;
const BASE_FIELD_BITS: usize = 31;

fn main() {
    let num_vars = 10;
    let block_size = 2;
    let lookup_num = 2;
    let range = 1024;

    let mut rng = thread_rng();
    let f_vec: Vec<Rc<DenseMultilinearExtension<FF>>> = (0..lookup_num)
        .map(|_| {
            let f_evaluations: Vec<FF> = (0..(1 << num_vars))
                .map(|_| FF::new(rng.gen_range(0..range)))
                .collect();
            Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                num_vars,
                f_evaluations,
            ))
        })
        .collect();

    let mut t_evaluations: Vec<_> = (0..range as usize).map(|i| FF::new(i as u32)).collect();
    t_evaluations.resize(1 << num_vars, FF::zero());
    let t = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        t_evaluations,
    ));

    let instance = LookupInstance::from_slice(&f_vec, t.clone(), block_size);

    let code_spec = ExpanderCodeSpec::new(0.1195, 0.0248, 1.9, BASE_FIELD_BITS, 10);
    <LookupSnarks<FF, EF>>::snarks::<Hash, ExpanderCode<FF>, ExpanderCodeSpec>(
        &instance, &code_spec,
    );
}
