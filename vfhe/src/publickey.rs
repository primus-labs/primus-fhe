/// LWE Public key
pub type LWEPublicKey<R> = Vec<lattice::LWE<R>>;

/// RLWE Public key
pub type RLWEPublicKey<F> = lattice::RLWE<F>;
