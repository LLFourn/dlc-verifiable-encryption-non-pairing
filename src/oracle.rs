use crate::G;
use curve25519_dalek::{ristretto::RistrettoPoint as Point, scalar::Scalar};
use rand::{CryptoRng, RngCore};

#[allow(dead_code)]
pub struct Oracle {
    sk: Scalar,
    pk: Point,
    nsk: Vec<Scalar>,
    npk: Vec<Point>,
}

impl Oracle {
    pub fn random(n_outcomes: u32, rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let n_nonces = (n_outcomes as f32).log2().ceil() as usize;
        Self::new(
            Scalar::random(rng),
            (0..n_nonces).map(|_| Scalar::random(rng)).collect(),
        )
    }

    pub fn new(sk: Scalar, nsk: Vec<Scalar>) -> Self {
        let pk = &sk * &*G;
        let npk = nsk.iter().map(|nsk| nsk * &*G).collect();
        Self { sk, pk, nsk, npk }
    }

    pub fn public_key(&self) -> Point {
        self.pk
    }

    pub fn public_nonce(&self) -> &[Point] {
        &self.npk
    }

    pub fn attest(&self, outcome_index: u32) -> Vec<Scalar> {
        (0..self.nsk.len())
            .map(|bit_index| {
                let bit_value = ((outcome_index >> bit_index) & 0x01) == 1;
                let nsk = &self.nsk[bit_index];
                let nonce_coef = Scalar::from(bit_value as u32 + 1);
                nonce_coef * nsk + self.sk
            })
            .collect()
    }
}
