pub struct Param {
    n: usize,
    err_std_dev: f64,
}

impl Param {
    pub fn new(n: usize, err_std_dev: f64) -> Self {
        Self { n, err_std_dev }
    }
}

pub struct Params {
    lwe: Param,
    rlwe: Param,
}

impl Params {
    pub fn new(lwe: Param, rlwe: Param) -> Self {
        Self { lwe, rlwe }
    }
}
