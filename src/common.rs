use curve25519_dalek::{ristretto::RistrettoPoint as Point, scalar::Scalar};
use sha2::{digest::Digest, Sha256};

#[derive(Clone, Debug)]
pub struct Params {
    pub closed_proportion: f64,
    pub bucket_size: u8,
    pub elgamal_base: Point,
    pub n_encryptions: usize,
}

impl Params {
    pub fn M(&self) -> usize {
        (self.NB() as f64 / self.closed_proportion).ceil() as usize
    }

    pub fn NB(&self) -> usize {
        self.n_encryptions * self.bucket_size as usize
    }

    pub fn num_openings(&self) -> usize {
        self.M() - self.NB()
    }
}

pub fn map_Zq_to_G(ri: &Scalar) -> (Point, [u8; 32]) {
    let point = Point::random(&mut rand::thread_rng());
    let mut hashed_xor_ri = Sha256::default()
        .chain(point.compress().to_bytes())
        .finalize();
    for (xor_byte, ri_byte) in hashed_xor_ri.iter_mut().zip(ri.to_bytes()) {
        *xor_byte ^= ri_byte
    }
    (point, hashed_xor_ri.try_into().unwrap())
}

pub fn map_G_to_Zq(point: Point, pad: [u8; 32]) -> Scalar {
    let mut ri_bytes = Sha256::default()
        .chain(point.compress().to_bytes())
        .finalize();
    for (xor_byte, pad_byte) in ri_bytes.iter_mut().zip(pad) {
        *xor_byte ^= pad_byte
    }
    Scalar::from_bytes_mod_order(ri_bytes.try_into().unwrap())
}

pub fn compute_optimal_params(security_param: u8, n_encryptions: usize) -> (f64, u8) {
    if n_encryptions == 1 {
        // this is cheating and not quite right
        return (0.5, security_param);
    }
    let N = n_encryptions as f64;
    let s = security_param as f64;

    let (B, p, _) = (500..999)
        .filter_map(|p| {
            let p = (p as f64) / 1000.0;
            // requirement for the formula below to hold
            if N < (1.0 / (1.0 - p)) {
                return None;
            }
            let B = ((s as f64 + (N as f64).log2() - p.log2())
                / ((N - N * p).log2() - p.log2() / (1.0 - p)))
                .ceil();
            let score = ((B * N) / p).ceil() as u64;
            Some((B as u8, p, score))
        })
        .min_by_key(|(_, _, score)| *score)
        .unwrap();

    (p, B)
}
