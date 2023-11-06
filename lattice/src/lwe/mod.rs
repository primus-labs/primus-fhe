use algebra::field::Field;

pub struct Lwe<F: Field> {
    a: Vec<F>,
    b: F,
}
