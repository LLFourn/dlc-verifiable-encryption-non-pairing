use schnorr_fun::fun::{marker::*, Point, Scalar};
use std::collections::BTreeSet;
use crate::poly::PointPoly;

#[derive(Debug, Clone)]
pub struct Message1 {
    pub commits: Vec<Commit>,
}

#[derive(Debug, Clone, Default, Copy)]
pub struct Commit {
    pub C: (Point, Point),
    pub R: Point,
    pub pad: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct Message2 {
    pub bucket_mapping: Vec<usize>,
    pub openings: BTreeSet<usize>,
}

#[derive(Debug, Clone)]
pub struct Message3 {
    pub encryptions: Vec<(crate::dleq::Proof, Point, Scalar<Secret, Zero>)>,
    pub polys: Vec<PointPoly>,
    pub openings: Vec<Scalar>,
}
