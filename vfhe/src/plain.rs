use algebra::ring::Ring;

pub struct Plaintext<R: Ring> {
    m: R,
}

impl<R: Ring> Plaintext<R> {
    pub fn new(m: R) -> Self {
        Self { m }
    }

    pub fn encode(m:R::Base,t:R::Base) {
        
    }
}
