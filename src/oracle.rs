use secp256kfun::{g, marker::*, s, Point, Scalar, G};
#[allow(dead_code)]
pub struct Oracle {
    sk: Scalar,
    pk: Point,
}

impl Oracle {
    pub fn new(sk: Scalar) -> Self {
        let pk = g!(sk * G).normalize();
        Self { sk, pk }
    }

    pub fn public_key(&self) -> Point {
        self.pk
    }

    pub fn attest(&self, nonce: Scalar, i: usize) -> Scalar<Public, Zero> {
        let i = Scalar::from(i as u32);
        s!(nonce * (i + 1) + self.sk).mark::<Public>()
    }
}
