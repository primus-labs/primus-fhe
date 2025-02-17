use mpc::{MPCBackend, MPCId};
use rand::Rng;

pub fn generate_shared_binary_value_two_field<Backendq, BackendQ, R>(
    backend_q: &mut Backendq,
    backend_big_q: &mut BackendQ,
    rng: &mut R,
) -> (MPCId, MPCId)
where
    Backendq: MPCBackend,
    BackendQ: MPCBackend,
    R: Rng,
{
    let id = backend_q.id().0 as u32;
    let t = backend_q.num_threshold();

    let b_vec: Vec<(MPCId, MPCId)> = (0..t)
        .map(|i| {
            if id == i {
                let b = rng.gen_bool(0.5) as u64;
                (
                    backend_q.input(Some(b), id).unwrap(),
                    backend_big_q.input(Some(b), id).unwrap(),
                )
            } else {
                (
                    backend_q.input(None, id).unwrap(),
                    backend_big_q.input(None, id).unwrap(),
                )
            }
        })
        .collect();

    b_vec
        .into_iter()
        .reduce(|(b_q_x, b_big_q_x), (b_q_y, b_big_q_y)| {
            let temp1 = backend_q.add(b_q_x, b_q_y).unwrap();
            let temp2 = backend_q.mul(b_q_x, b_q_y).unwrap();
            let temp3 = backend_q.double(temp2).unwrap();

            let temp4 = backend_big_q.add(b_big_q_x, b_big_q_y).unwrap();
            let temp5 = backend_big_q.mul(b_big_q_x, b_big_q_y).unwrap();
            let temp6 = backend_big_q.double(temp5).unwrap();

            (
                backend_q.sub(temp1, temp3).unwrap(),
                backend_big_q.sub(temp4, temp6).unwrap(),
            )
        })
        .unwrap()
}

pub fn generate_shared_ternary_value_two_field<Backendq, BackendQ, R>(
    backend_q: &mut Backendq,
    backend_big_q: &mut BackendQ,
    rng: &mut R,
) -> (MPCId, MPCId)
where
    Backendq: MPCBackend,
    BackendQ: MPCBackend,
    R: Rng,
{
    let (b_q1, b_big_q1) = generate_shared_binary_value_two_field(backend_q, backend_big_q, rng);
    let (b_q2, b_big_q2) = generate_shared_binary_value_two_field(backend_q, backend_big_q, rng);
    (
        backend_q.sub(b_q1, b_q2).unwrap(),
        backend_big_q.sub(b_big_q1, b_big_q2).unwrap(),
    )
}

pub fn generate_shared_binary_value<Backend, R>(backend: &mut Backend, rng: &mut R) -> MPCId
where
    Backend: MPCBackend,
    R: Rng,
{
    let t = backend.num_threshold();
    let id = backend.id().0 as u32;

    let b_vec: Vec<MPCId> = (0..t)
        .map(|i| {
            if id == i {
                backend.input(Some(rng.gen_bool(0.5) as u64), id).unwrap()
            } else {
                backend.input(None, id).unwrap()
            }
        })
        .collect();

    b_vec
        .into_iter()
        .reduce(|b_x, b_y| {
            let temp1 = backend.add(b_x, b_y).unwrap();
            let temp2 = backend.mul(b_x, b_y).unwrap();
            let temp3 = backend.double(temp2).unwrap();
            backend.sub(temp1, temp3).unwrap()
        })
        .unwrap()
}

pub fn generate_shared_ternary_value<Backend, R>(backend: &mut Backend, rng: &mut R) -> MPCId
where
    Backend: MPCBackend,
    R: Rng,
{
    let b1 = generate_shared_binary_value(backend, rng);
    let b2 = generate_shared_binary_value(backend, rng);
    backend.sub(b1, b2).unwrap()
}
