use curve25519_dalek::{scalar::Scalar, ristretto::RistrettoPoint as Point};
use crate::G;
use zkp::{toolbox::{prover::Prover, SchnorrCS, verifier::Verifier}, BatchableProof};

pub type Proof = BatchableProof;

pub fn prove_eqaulity(
    prover: &mut Prover<'_>,
    ri_prime: Scalar,
    ri_encryption: Point,
    sig_point: Point,
    commit_base: Point,
    commit: (Point, Point),
) {
    let enc_sub = ri_encryption - commit.1;
    let sig_sub = sig_point - commit_base ;
    let statement = ((G.basepoint(), commit.0), (sig_sub, enc_sub));
    let witness = prover.allocate_scalar(b"ri_prime", ri_prime);

    let p_0_0 = prover.allocate_point(b"0.0", statement.0.0).0;
    let p_0_1 = prover.allocate_point(b"0.1", statement.0.1).0;
    let p_1_0 = prover.allocate_point(b"1.0", statement.1.0).0;
    let p_1_1 = prover.allocate_point(b"1.1", statement.1.1).0;

    prover.constrain(p_0_1, vec![(witness, p_0_0)]);
    prover.constrain(p_1_1, vec![(witness, p_1_0)]);
}

pub fn verify_eqaulity(
    verifier: &mut Verifier<'_>,
    ri_encryption: Point,
    sig_point: Point,
    commit_base: Point,
    commit: (Point, Point),
) {
    let enc_sub =ri_encryption - commit.1;
    let sig_sub =sig_point - commit_base;
    let statement = ((G.basepoint(), commit.0), (sig_sub, enc_sub));
    let witness_var = verifier.allocate_scalar(b"ri_prime");

    let p_0_0 = verifier.allocate_point(b"0.0", statement.0.0.compress()).unwrap();
    let p_0_1 = verifier.allocate_point(b"0.1", statement.0.1.compress()).unwrap();
    let p_1_0 = verifier.allocate_point(b"1.0", statement.1.0.compress()).unwrap();
    let p_1_1 = verifier.allocate_point(b"1.1", statement.1.1.compress()).unwrap();

    verifier.constrain(p_0_1, vec![(witness_var, p_0_0)]);
    verifier.constrain(p_1_1, vec![(witness_var, p_1_0)]);
}
