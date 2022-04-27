use rand::{CryptoRng, RngCore};
use curve25519_dalek::{scalar::Scalar, ristretto::RistrettoPoint as Point};
use crate::G;

#[allow(dead_code)]
pub struct Oracle {
    sk: Scalar,
    pk: Point,
    nsk: Scalar,
    npk: Point,
}

impl Oracle {
    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self::new(Scalar::random(rng), Scalar::random(rng))
    }

    pub fn new(sk: Scalar, nsk: Scalar) -> Self {
        let pk = &sk * &*G;
        let npk = &nsk * &*G;
        Self { sk, pk, nsk, npk }
    }

    pub fn public_key(&self) -> Point {
        self.pk
    }

    pub fn public_nonce(&self) -> Point {
        self.npk
    }

    pub fn attest(&self, i: u32) -> Scalar {
        let i = Scalar::from(i + 1);
        self.nsk * i + self.sk
    }
}
