use primus_integer::BigUint;
use primus_modulus::BarrettModulus;
use primus_rns::RNSBase;

type ValueT = u64;

#[test]
fn test_rns() {
    let moduli = [3, 5, 7].map(BarrettModulus::<ValueT>::new);
    let base = RNSBase::new(&moduli).unwrap();

    let residues = &[2, 3, 2];
    let value = base.compose(residues);
    let dec = base.decompose(value.view());
    assert_eq!(dec, residues);
}

#[test]
fn test_rns2() {
    let moduli = [256, 257].map(BarrettModulus::<ValueT>::new);
    let base = RNSBase::new(&moduli).unwrap();

    let residues = &[2, 3];
    let value = base.compose(residues);
    let dec = base.decompose(value.view());
    assert_eq!(dec, residues);
}

#[test]
fn test_rns3() {
    let moduli_value: [ValueT; 2] = [1099511592961, 1099511590913];
    let moduli = moduli_value.map(<BarrettModulus<ValueT>>::new);
    let base_q = RNSBase::new(&moduli).unwrap();
    let q = base_q.moduli_product();

    let t = 257;
    for r in 0..t {
        let input: [ValueT; 2] = [r, 0];

        println!("{:?}", base_q.decompose(BigUint(&input)));

        let mut input: BigUint<[ValueT; 2]> = BigUint([0; 2]);
        if r < t.div_ceil(2) {
            input[0] = r;
        } else {
            let _ = q.sub_value_to(t - r, &mut input);
        }

        let d = base_q.decompose(input.view());

        if r < t.div_ceil(2) {
            assert_eq!(d[0], r);
            assert_eq!(d[1], r);
        } else {
            assert_eq!(d[0], moduli_value[0] - (t - r));
            assert_eq!(d[1], moduli_value[1] - (t - r));
        }

        println!("{:?}", d);
    }
}
