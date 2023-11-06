use algebra::field::Field;

pub struct Rlwe<F: Field> {
    a: Vec<F>,
    b: Vec<F>,
}
