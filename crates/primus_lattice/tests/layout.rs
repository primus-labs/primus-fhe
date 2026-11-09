//! Checked layout boundaries and RNS scratch compatibility.

use primus_decompose::DecompositionLevelCount;
use primus_lattice::{
    GadgetSize, GlweDimension, GlweSize, GlweSizeError, RnsGadgetSize, RnsGlweSize,
};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_shape::{MAX_POLY_LENGTH, MIN_POLY_LENGTH, PolyLength};

#[test]
fn dimensions_validate_body_counts_and_derive_extracted_lwe_layouts() {
    use primus_lattice::{GlweDimension, LweDimension};
    for invalid in [0, usize::MAX] {
        assert!(LweDimension::try_new(invalid).is_err());
        assert!(GlweDimension::try_new(invalid).is_err());
    }
    // No allocation or preset limit is implied by a dimension alone.
    assert_eq!(
        LweDimension::new(usize::MAX - 1).ciphertext_len(),
        usize::MAX
    );
    assert_eq!(
        GlweDimension::new(usize::MAX - 1).component_count(),
        usize::MAX
    );
    for (k, n) in [(1, 32), (3, 64), (usize::MAX / 32 - 1, 32)] {
        let size = GlweSize::new(GlweDimension::new(k), PolyLength::new(n));
        let extracted_dimension = LweDimension::from(size);
        assert_eq!(size.mask_len(), k * n);
        assert_eq!(extracted_dimension.get(), k * n);
        assert_eq!(extracted_dimension.ciphertext_len(), k * n + 1);
        assert_eq!(size.glwe_len(), (k + 1) * n);
        assert_eq!(LweDimension::from(size.poly_length()).get(), n);
    }
}

#[test]
fn checked_sizes_reject_empty_and_overflowing_layouts() {
    assert!(GlweSize::try_new(GlweDimension::new(1), PolyLength::new(MIN_POLY_LENGTH)).is_ok());
    assert!(GlweSize::try_new(GlweDimension::new(1), PolyLength::new(MAX_POLY_LENGTH)).is_ok());

    let glwe = GlweSize::new(GlweDimension::new(1), PolyLength::new(32));
    assert_eq!(
        RnsGlweSize::try_new(glwe, 0),
        Err(GlweSizeError::ZeroModuliCount)
    );
    assert!(matches!(
        GlweSize::try_new(GlweDimension::new(usize::MAX - 1), PolyLength::new(32)),
        Err(GlweSizeError::LengthOverflow(_))
    ));
    assert!(matches!(
        GadgetSize::try_new(glwe, DecompositionLevelCount::new(usize::MAX)),
        Err(GlweSizeError::LengthOverflow("GLev ciphertext"))
    ));
    assert!(matches!(
        RnsGlweSize::try_new(glwe, usize::MAX),
        Err(GlweSizeError::LengthOverflow(_))
    ));

    // Each GLev fits; combining k+1 such rows into a GGSW overflows.
    // Only size descriptors are constructed, never ciphertext buffers.
    let levels = DecompositionLevelCount::new(usize::MAX / glwe.glwe_len());
    assert_eq!(
        GadgetSize::try_new(glwe, levels),
        Err(GlweSizeError::LengthOverflow("GGSW ciphertext"))
    );
    let rns_glwe = RnsGlweSize::new(glwe, 2);
    let levels = DecompositionLevelCount::new(usize::MAX / rns_glwe.rns_glwe_len());
    assert_eq!(
        RnsGadgetSize::try_new(rns_glwe, levels),
        Err(GlweSizeError::LengthOverflow("RNS GGSW ciphertext"))
    );
}

#[cfg(feature = "rns")]
#[test]
fn dcrt_workspace_reuse_depends_on_layout_and_limb_width() {
    use primus_lattice::workspace::DcrtGlevMulWorkspace;
    use primus_rns::RNSBase;
    let size = RnsGadgetSize::new(
        RnsGlweSize::new(GlweSize::new(GlweDimension::new(1), PolyLength::new(32)), 2),
        DecompositionLevelCount::new(3),
    );
    let small = RNSBase::new(&[17u32, 97].map(BarrettModulus::new)).unwrap();
    let other_small = RNSBase::new(&[19u32, 101].map(BarrettModulus::new)).unwrap();
    let large = RNSBase::new(&[65537u32, 65539].map(BarrettModulus::new)).unwrap();
    let workspace = DcrtGlevMulWorkspace::new(size, &small);

    assert_eq!(small.big_uint_value_len(), 1);
    assert_eq!(large.big_uint_value_len(), 2);
    assert!(workspace.is_compatible(size, &small));
    assert!(workspace.is_compatible(size, &other_small));
    assert!(!workspace.is_compatible(size, &large));
    let other_size = RnsGadgetSize::new(
        RnsGlweSize::new(GlweSize::new(GlweDimension::new(1), PolyLength::new(64)), 2),
        DecompositionLevelCount::new(3),
    );
    assert!(!workspace.is_compatible(other_size, &small));
}

#[cfg(all(feature = "ntt", feature = "fourier"))]
#[test]
fn serial_external_product_restores_ternary_layout_on_unwind() {
    use primus_lattice::workspace::{FourierGlweTernaryCmuxWorkspace, NttGlweTernaryCmuxWorkspace};
    use std::panic::{AssertUnwindSafe, catch_unwind};

    // Rebinding changes the serial consumer's level count, never its GLWE
    // geometry. An unwinding consumer must not leave that temporary binding.
    const N: usize = 32;
    let original = GadgetSize::new(
        GlweSize::new(GlweDimension::new(1), PolyLength::new(N)),
        DecompositionLevelCount::new(3),
    );
    let temporary = GadgetSize::new(
        GlweSize::new(GlweDimension::new(1), PolyLength::new(N)),
        DecompositionLevelCount::new(2),
    );
    let mut ntt = NttGlweTernaryCmuxWorkspace::<u32>::new(original);
    let mut fourier = FourierGlweTernaryCmuxWorkspace::<u64>::new(original);
    assert!(
        catch_unwind(AssertUnwindSafe(|| ntt.with_external_product(
            temporary,
            |scratch| {
                assert_eq!(scratch.size(), temporary);
                panic!("interrupted consumer");
            }
        )))
        .is_err()
    );
    assert!(
        catch_unwind(AssertUnwindSafe(|| fourier.with_external_product(
            temporary,
            |scratch| {
                assert_eq!(scratch.size(), temporary);
                panic!("interrupted consumer");
            }
        )))
        .is_err()
    );
    assert_eq!(ntt.size(), original);
    assert_eq!(fourier.size(), original);

    // A shape mismatch is rejected before invoking the consumer, leaving the
    // workspace available for its original layout in release as well as debug.
    let different = GadgetSize::new(
        GlweSize::new(GlweDimension::new(1), PolyLength::new(2 * N)),
        DecompositionLevelCount::new(3),
    );
    let mut called = false;
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            ntt.with_external_product(different, |_| called = true);
        }))
        .is_err()
    );
    assert!(!called);
    assert_eq!(ntt.size(), original);
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            fourier.with_external_product(different, |_| called = true);
        }))
        .is_err()
    );
    assert!(!called);
    assert_eq!(fourier.size(), original);
}

#[test]
fn consuming_negation_reuses_aligned_and_borrowed_storage() {
    use primus_lattice::lwe::Lwe;

    // ABox supports the same DataMut contract as an ordinary mutable slice;
    // consuming a wrapper must keep its allocation, including for u64 torus data.
    let ciphertext = Lwe::new(aligned_vec::avec![0u64, u64::MAX, u64::MAX - 6].into_boxed_slice());
    let original_pointer = ciphertext.as_ref().as_ptr();
    let view: Lwe<&[u64]> = (&ciphertext).into();
    assert_eq!(view.as_ref().as_ptr(), original_pointer);
    let ciphertext = ciphertext.neg(NativeModulus::new());
    assert_eq!(ciphertext.as_ref().as_ptr(), original_pointer);
    assert_eq!(ciphertext.as_ref(), &[0, 1, 7]);

    let storage = ciphertext.into_inner();
    assert_eq!(storage.as_ptr(), original_pointer);

    let mut storage = [99u32, 0, 96, 45, 99];
    let mut ciphertext = Lwe::new(&mut storage[1..4]);
    let view: Lwe<&mut [u32]> = (&mut ciphertext).into();
    let ciphertext = view.neg(BarrettModulus::new(97));
    assert_eq!(ciphertext.as_ref(), &[0, 1, 52]);
    assert_eq!(storage, [99, 0, 1, 52, 99]);
}
