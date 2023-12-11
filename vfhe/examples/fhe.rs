use algebra::derive::*;
use vfhe::{Param, Params, Vfhe};

fn main() {
    let lwe_param = <Param<RR>>::new(1024, 3.20);
    let rlwe_param = <Param<FF>>::new(2048, 3.20);

    let fhe_params = Params::new(lwe_param, rlwe_param);

    let _vfhe = Vfhe::new(fhe_params);
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd, Ord, Ring, Random)]
#[modulus = 512]
pub struct RR(u32);

#[derive(
    Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd, Ord, Ring, Field, Random, Prime, NTT,
)]
#[modulus = 132120577]
pub struct FF(u32);
