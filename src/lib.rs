#![allow(non_snake_case)]
pub mod alice;
pub mod bob;
pub mod common;
pub mod dleq;
pub mod messages;
pub mod poly;

lazy_static::lazy_static! {
    pub static ref G: curve25519_dalek::ristretto::RistrettoBasepointTable = {
        curve25519_dalek::ristretto::RistrettoBasepointTable::create(&curve25519_dalek::ristretto::RistrettoPoint::random(&mut rand::thread_rng()))
    };
}
