use fhe_core::Code;

fn main() {
    let real_message_size = 64;
    let q = 8192;
    let coder = <Code<u8, u16>>::new(real_message_size, real_message_size * 2, q);

    let noise_max = q / (real_message_size * 4);

    let message = 61;
    let encoded = coder.encode(message);
    println!("Encode:{}->{}", message, encoded);
    let decoded = coder.decode(encoded + noise_max - 1);
    println!("Decode:{}->{}", encoded, decoded);
    let decoded = coder.decode(encoded - noise_max + 1);
    println!("Decode:{}->{}", encoded, decoded);
}
