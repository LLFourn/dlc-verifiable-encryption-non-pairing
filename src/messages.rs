use crate::poly::PointPoly;
use curve25519_dalek::{ristretto::RistrettoPoint as Point, scalar::Scalar};
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
    pub bit_map_images: Vec<Vec<[Point; 2]>>,
    // there is one of these per outcome ( per oracle )
    pub secret_share_pads_by_oracle: Vec<Vec<Scalar>>,
}
