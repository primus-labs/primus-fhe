use algebra::modulus::PowOf2Modulus;
use algebra::reduce::{AddReduce, SubReduce};
use fhe_core::{decode, encode};

type M = u8;
type C = u16;

fn main() {
    let t: u64 = 4;
    let q: u64 = 512;

    // q/2t
    let noise_max = (q / (t * 2)) as C;

    let modulus = PowOf2Modulus::<u16>::new(q as C);

    // check all message are encoded and decoded correctly, even with noise.
    for i in 0..t {
        let message: M = i.try_into().unwrap();

        let encoded: C = encode(message, t, q);

        let decoded: M = decode(encoded, t, q);
        assert_eq!(decoded, message);

        // add noise
        let decoded: M = decode(encoded.add_reduce(noise_max - 1, modulus), t, q);
        assert_eq!(decoded, message);

        // sub noise
        let decoded: M = decode(encoded.sub_reduce(noise_max - 1, modulus), t, q);
        assert_eq!(decoded, message);
    }
}
