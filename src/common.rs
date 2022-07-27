use curve25519_dalek::{ristretto::RistrettoPoint as Point, scalar::Scalar};
use sha2::{digest::Digest, Sha256};

#[derive(Clone, Debug)]
pub struct Params {
    pub oracle_keys: Vec<(Point, Vec<Point>)>,
    pub closed_proportion: f64,
    pub bucket_size: u8,
    pub threshold: u16,
    pub n_outcomes: u32,
    pub elgamal_base: Point,
}

impl Params {
    pub fn M(&self) -> usize {
        (self.NB() as f64 / self.closed_proportion).ceil() as usize
    }

    pub fn n_outcome_bits(&self) -> u32 {
        (self.n_outcomes as f32).log2().ceil() as u32
    }

    pub fn n_anticipations_per_oracle(&self) -> u32 {
        self.n_outcome_bits() * 2
    }

    pub fn NB(&self) -> usize {
        self.bucket_size as usize
            * self.n_anticipations_per_oracle() as usize
            * self.oracle_keys.len()
    }

    pub fn num_openings(&self) -> usize {
        self.M() - self.NB()
    }

    pub fn iter_anticipations(&self, oracle_index: usize) -> impl Iterator<Item = [Point; 2]> + '_ {
        let pk = self.oracle_keys[oracle_index].0;
        let nonces = &self.oracle_keys[oracle_index].1;
        (0..self.n_outcome_bits()).map(move |bit| {
            let zero = pk + &nonces[bit as usize];
            let one = zero + &nonces[bit as usize];
            [zero, one]
        })
    }

    pub fn anticipate_at_index(
        &self,
        oracle_index: usize,
        oracle_bit_index: u32,
        outcome_bit_value: bool,
    ) -> Point {
        let nonce_coef = Scalar::from(outcome_bit_value as u32 + 1);
        let (oracle_key, oracle_nonces) = &self.oracle_keys[oracle_index];
        oracle_key + nonce_coef * &oracle_nonces[oracle_bit_index as usize]
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

pub fn compute_optimal_params(security_param: u8, n_outcomes: u32, n_oracles: u32) -> (f64, u8) {
    if n_outcomes * n_oracles == 1 {
        // this is cheating and not quite right
        return (0.5, security_param);
    }
    let n_outcomes = n_outcomes as f64;
    let mut n_encryptions = n_outcomes.log2().ceil() * 2.0;
    if n_encryptions == 0.0 {
        n_encryptions = 1.0;
    }
    let n_oracles = n_oracles as f64;
    let N = n_encryptions * n_oracles;
    // we can afford to remove 1 bit of security since for any corruption the adversary makes there
    // is a 1/2 chance that that outcome is actually selected.
    let s = security_param as f64 - 1.0;

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

pub fn to_bits(mut num: u32, bit_length: usize) -> Vec<bool> {
    (0..bit_length)
        .map(|_| {
            let bit = num & 0x01 == 1;
            num = num >> 1;
            bit
        })
        .collect()
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_to_bits() {
        assert_eq!(to_bits(0x01, 2), vec![true, false]);
        assert_eq!(to_bits(0x3, 2), vec![true, true]);
    }
}
