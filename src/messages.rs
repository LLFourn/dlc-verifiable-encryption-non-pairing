use crate::poly::PointPoly;
use curve25519_dalek::{scalar::Scalar, ristretto::RistrettoPoint as Point};
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize)]
pub struct Message1 {
    pub commits: Vec<Commit>,
}

#[derive(Debug, Clone, Default, Copy, Serialize)]
pub struct Commit {
    pub C: (Point, Point),
    pub R: Point,
    pub pad: [u8; 32],
}

#[derive(Debug, Clone, Serialize)]
pub struct Message2 {
    pub bucket_mapping: Vec<usize>,
    pub openings: BTreeSet<usize>,
}

#[derive(Clone, Serialize)]
pub struct Message3 {
    pub proof: crate::dleq::Proof,
    pub encryptions: Vec<(Point, Scalar)>,
    pub polys: Vec<PointPoly>,
    pub openings: Vec<Scalar>,
}
