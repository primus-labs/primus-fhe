use algebra::modulus::PowOf2Modulus;
use algebra::reduce::{AddReduce, SubReduce};
use fhe_core::{decode, encode};

type M = u8;
type C = u16;

fn main() {
    let m: u64 = 64;
    let t: u64 = 128;
    let q: u64 = 8192;

    let delta = q / t;
    let delta_trailing_zeros = delta.trailing_zeros();

    let noise_max = (q / (m * 4)) as C;

    let modulus = PowOf2Modulus::<u16>::new(q as C);

    let message: M = 0;
    let encoded: C = encode(message, m, delta_trailing_zeros);
    println!("Encode:{}->{}", message, encoded);
    let decoded: M = decode(
        encoded.add_reduce(noise_max - 1, modulus),
        m,
        delta_trailing_zeros,
    );
    println!("Decode:{}->{}", encoded, decoded);
    let decoded: M = decode(
        encoded.sub_reduce(noise_max - 1, modulus),
        m,
        delta_trailing_zeros,
    );
    println!("Decode:{}->{}", encoded, decoded);
}
