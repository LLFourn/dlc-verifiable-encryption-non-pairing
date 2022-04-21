use secp256kfun::{g, marker::*, Point, Scalar};
use sha2::{digest::Digest, Sha256};

pub struct Params {
    pub oracle_key: Point,
    pub oracle_nonce: Point,
    pub closed_proportion: f32,
    pub bucket_size: usize,
    pub n_outcomes: usize,
    pub elgamal_base: Point,
}

impl Params {
    pub fn M(&self) -> usize {
        ((self.bucket_size * self.n_outcomes) as f32 / self.closed_proportion).ceil() as usize
    }

    pub fn NB(&self) -> usize {
        self.n_outcomes * self.bucket_size
    }

    pub fn num_openings(&self) -> usize {
        self.M() - self.NB()
    }

    pub fn iter_anticipations(&self) -> impl Iterator<Item = Point<Jacobian, Public, Zero>> {
        let mut acc = self.oracle_key.clone().mark::<(Jacobian, Zero)>();
        let nonce = self.oracle_nonce.clone();
        (0..self.n_outcomes).map(move |_| {
            acc = g!(nonce + acc);
            acc
        })
    }

    pub fn anticipate_at_index(&self, index: u32) -> Point<Jacobian, Public, Zero> {
        let index = Scalar::from(index);
        g!(self.oracle_key + (index + 1) * self.oracle_nonce)
    }
}

pub fn map_Zq_to_G(ri: &Scalar) -> (Point, [u8; 32]) {
    let point = Point::random(&mut rand::thread_rng());
    let mut hashed_xor_ri = Sha256::default().chain(point.to_bytes()).finalize();
    for (xor_byte, ri_byte) in hashed_xor_ri.iter_mut().zip(ri.to_bytes()) {
        *xor_byte ^= ri_byte
    }
    (point, hashed_xor_ri.try_into().unwrap())
}

pub fn map_G_to_Zq(point: Point, pad: [u8; 32]) -> Scalar<Secret, Zero> {
    let mut ri_bytes = Sha256::default().chain(point.to_bytes()).finalize();
    for (xor_byte, pad_byte) in ri_bytes.iter_mut().zip(pad) {
        *xor_byte ^= pad_byte
    }
    Scalar::from_bytes_mod_order(ri_bytes.try_into().unwrap())
}
