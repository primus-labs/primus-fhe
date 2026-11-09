use primus_bgv::{BgvContext, BgvContextError, BgvParameters};
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_ntt::U64DcrtTable;
use primus_shape::PolyLength;
use std::sync::Arc;

const Q: [u64; 3] = [
    1_125_899_906_248_961,
    1_125_899_906_051_329,
    1_125_899_904_322_049,
];

fn parameters() -> BgvParameters {
    BgvParameters::try_coefficients(
        PolyLength::new(32),
        BarrettModulus::new(193),
        &Q.map(BarrettModulus::new),
        SecretKeyDistr::SparseTernary,
        0.849,
    )
    .unwrap()
}

#[test]
fn shared_table_keeps_actual_transform_and_rejects_foreign_geometry() {
    let context = BgvContext::try_with_levels(parameters(), 3).unwrap();
    let shared = BgvContext::try_with_table(parameters(), 3, context.shared_table()).unwrap();
    assert!(std::ptr::eq(context.table(), shared.table()));
    assert_eq!(shared.base_q(1).moduli_values(), &Q[..2]);
    assert_eq!(shared.base_q(2).moduli_values(), &Q[..1]);

    for (n, q) in [
        (64, Q.to_vec()),
        (32, vec![Q[1], Q[0], Q[2]]),
        (32, Q[..2].to_vec()),
    ] {
        let moduli: Vec<_> = q.into_iter().map(BarrettModulus::new).collect();
        let foreign = Arc::new(U64DcrtTable::new(PolyLength::new(n), &moduli).unwrap());
        assert!(matches!(
            BgvContext::try_with_table(parameters(), 3, foreign),
            Err(BgvContextError::Binding(_))
        ));
    }
    for count in [0, 4] {
        assert!(matches!(
            BgvContext::try_with_table(parameters(), count, context.shared_table()),
            Err(BgvContextError::LevelCount { .. })
        ));
    }
}
