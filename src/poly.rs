use rand::{CryptoRng, RngCore};
use curve25519_dalek::{scalar::Scalar, ristretto::RistrettoPoint as Point, traits::VartimeMultiscalarMul};
use serde::Serialize;
use std::iter;
use crate::G;

#[derive(Clone, Debug, PartialEq)]
pub struct ScalarPoly(Vec<Scalar>);

impl ScalarPoly {
    pub fn eval(&self, x: u32) -> Scalar {
        let x = Scalar::from(x);
        let mut xpow = Scalar::from(1u32);
        self.0
            .iter()
            .skip(1)
            .fold(self.0[0], move |sum, coeff| {
                xpow = xpow * x;
                sum + xpow * coeff
            })
    }

    pub fn to_point_poly(&self) -> PointPoly {
        PointPoly(self.0.iter().map(|a| a * &*G).collect())
    }

    pub fn random(n_coefficients: usize, rng: &mut (impl RngCore + CryptoRng)) -> Self {
        ScalarPoly((0..n_coefficients).map(|_| Scalar::random(rng)).collect())
    }

    pub fn poly_len(&self) -> usize {
        self.0.len()
    }

    pub fn new(x: Vec<Scalar>) -> Self {
        Self(x)
    }

    pub fn pop_front(&mut self) {
        self.0.remove(0);
    }

    pub fn push_front(&mut self, scalar: Scalar) {
        self.0.insert(0, scalar)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PointPoly(Vec<Point>);

impl PointPoly {
    pub fn eval(&self, x: u32) -> Point {
        let x = Scalar::from(x);
        let xpows = iter::successors(Some(Scalar::from(1u32)), |xpow| {
            Some(x * xpow)
        })
        .take(self.0.len())
        .collect::<Vec<_>>();

        Point::vartime_multiscalar_mul(xpows, &self.0)
    }

    pub fn poly_len(&self) -> usize {
        self.0.len()
    }

    pub fn points(&self) -> &[Point] {
        &self.0
    }

    pub fn pop_front(&mut self) {
        self.0.remove(0);
    }

    pub fn push_front(&mut self, point: Point) {
        self.0.insert(0, point)
    }
}
