/// public key
pub type LWEPublicKey<R> = Vec<lattice::LWE<R>>;

/// public key
pub type RLWEPublicKey<F> = lattice::RLWE<F>;
