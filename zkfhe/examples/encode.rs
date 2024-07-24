use algebra::modulus::PowOf2Modulus;
use algebra::reduce::{AddReduce, SubReduce};
use fhe_core::{decode, encode};

type M = u8;
type C = u16;

fn main() {
    let m: u64 = 2;
    let t: u64 = 4;
    let q: u64 = 512;

    let noise_max = (q / (m * 4)) as C;

    let modulus = PowOf2Modulus::<u16>::new(q as C);

    for i in 0..t {
        let message: M = i.try_into().unwrap();

        let encoded: C = encode(message, t, q);

        let decoded: M = decode(encoded, t, q);
        assert_eq!(decoded, message);

        // add noise
        let decoded: M = decode(encoded.add_reduce(noise_max - 1, modulus), t, q);
        assert_eq!(decoded, message);

        // add noise
        let decoded: M = decode(encoded.sub_reduce(noise_max - 1, modulus), t, q);
        assert_eq!(decoded, message);
    }
}
