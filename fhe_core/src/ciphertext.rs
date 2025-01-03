/// Lwe Ciphertext
pub type LweCiphertext<C> = lattice::Lwe<C>;

/// CmLwe Ciphertext
pub type CmLweCiphertext<C> = lattice::CmLwe<C>;

/// Rlwe Ciphertext
pub type RlweCiphertext<F> = lattice::Rlwe<F>;

/// Ntt version Rlwe Ciphertext
pub type NttRlweCiphertext<F> = lattice::NttRlwe<F>;
