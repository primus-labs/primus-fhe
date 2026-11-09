//! Storage capabilities are independent: collecting does not require consuming
//! iteration, and returning a buffer does not require owned constructors.

use std::sync::Arc;

use primus_modulus::NativeModulus;
use primus_poly::Polynomial;
use rand::{SeedableRng, rngs::StdRng};

#[test]
fn sampling_and_views_require_only_the_used_storage_capabilities() {
    // Arc supports collecting but has no consuming element iterator or DataOwned.
    // Sampling collects directly into either backend with the same seeded stream.
    let mut rng = StdRng::seed_from_u64(42);
    let mut same_rng = StdRng::seed_from_u64(42);
    let shared = Polynomial::<Arc<[u32]>>::random(8, NativeModulus::new(), &mut rng);
    let owned = Polynomial::<Vec<u32>>::random(8, NativeModulus::new(), &mut same_rng);
    assert_eq!(shared.as_view().as_ref(), owned.as_ref());

    // Returning owned or borrowed storage does not require DataOwned either.
    let storage = shared.into_inner();
    let borrowed = Polynomial::new(&storage).into_inner();
    assert!(core::ptr::eq(borrowed, &storage));
}
