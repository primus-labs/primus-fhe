//! Observe partially converted secrets before their allocation is released.

use primus_lattice::GlweDimension;
use primus_shape::PolyLength;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    panic::catch_unwind,
    ptr,
    sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering},
};

use primus_glwe_rns::{DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr};
use primus_lattice::GlweSize;
use primus_modulus::BarrettModulus;
use primus_ntt::{DcrtTable, NttError, NttTable, U64NttTable};
use primus_reduce::FieldContext;

struct ObservingAllocator;
static WATCHED: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());
static LENGTH: AtomicUsize = AtomicUsize::new(0);
static ERASED: AtomicBool = AtomicBool::new(false);

// SAFETY: System receives the original allocation/deallocation arguments. Only
// initialized secret bytes are observed, before the allocation is released.
unsafe impl GlobalAlloc for ObservingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller supplies a valid allocation layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, data: *mut u8, layout: Layout) {
        if WATCHED
            .compare_exchange(data, ptr::null_mut(), Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            let len = LENGTH.load(Ordering::SeqCst);
            let mut erased = len <= layout.size();
            for index in 0..len.min(layout.size()) {
                // SAFETY: the watched Vec is fully initialized and has not
                // resized; all observed bytes belong to the live allocation.
                erased &= unsafe { ptr::read_volatile(data.add(index)) } == 0;
            }
            ERASED.store(erased, Ordering::SeqCst);
        }
        // SAFETY: data/layout identify the allocation being released.
        unsafe { System.dealloc(data, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: ObservingAllocator = ObservingAllocator;

/// Register the first limb's allocation, then interrupt the second limb.
/// All other operations retain the real NTT implementation and its layout.
struct InterruptedTable(U64NttTable);

impl NttTable for InterruptedTable {
    type ValueT = u64;

    fn new<M: FieldContext<u64>>(
        poly_length: PolyLength,
        modulus: M,
    ) -> Result<Self, NttError<u64>> {
        U64NttTable::new(poly_length, modulus).map(Self)
    }

    fn poly_length(&self) -> PolyLength {
        self.0.poly_length()
    }

    fn modulus(&self) -> u64 {
        self.0.modulus()
    }

    fn lazy_transform_slice(&self, poly: &mut [u64]) {
        self.0.lazy_transform_slice(poly);
    }

    fn transform_slice(&self, poly: &mut [u64]) {
        assert!(poly.iter().any(|&coefficient| coefficient != 0));
        if self.modulus() == 193 {
            // The first limb starts at the allocation's base. Watch the whole
            // initialized key, including the not-yet-converted components.
            WATCHED.store(poly.as_mut_ptr().cast(), Ordering::SeqCst);
            self.0.transform_slice(poly);
        } else {
            assert_eq!(self.modulus(), 257);
            panic!("secret transform interrupted");
        }
    }

    fn lazy_inverse_transform_slice(&self, values: &mut [u64]) {
        self.0.lazy_inverse_transform_slice(values);
    }

    fn inverse_transform_slice(&self, values: &mut [u64]) {
        self.0.inverse_transform_slice(values);
    }
}

#[test]
fn partial_dcrt_secret_is_erased_on_transform_unwind() {
    let size = GlweSize::new(GlweDimension::new(2), PolyLength::new(32));
    let secret = GlweSecretKey::<u64>::new(
        vec![1; size.mask_len()],
        size,
        SecretKeyDistr::UniformBinary,
    );
    let moduli = [193u64, 257].map(BarrettModulus::new);
    let table = DcrtTable::<InterruptedTable>::new(size.poly_length(), &moduli).unwrap();
    LENGTH.store(
        size.mask_len() * moduli.len() * size_of::<u64>(),
        Ordering::SeqCst,
    );

    let result = catch_unwind(|| DcrtGlweSecretKey::from_coeff_secret_key(&secret, &table));
    assert!(result.is_err());
    assert!(
        WATCHED.load(Ordering::SeqCst).is_null(),
        "partial secret allocation was not released"
    );
    assert!(
        ERASED.load(Ordering::SeqCst),
        "partial secret allocation was released without erasure"
    );
}
