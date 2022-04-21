use rand_chacha::ChaCha20Rng;
use secp256kfun::{g, marker::*, Point, Scalar, G};
use sha2::Sha256;
use sigma_fun::{secp256k1::DL, typenum::U32, CompactProof, Eq, FiatShamir, HashTranscript};

type DLEQ = Eq<DL<U32>, DL<U32>>;
pub type Proof = CompactProof<DLEQ>;
pub type ProofSystem = FiatShamir<DLEQ, HashTranscript<Sha256, ChaCha20Rng>>;

pub fn prove_eqaulity(
    proof_system: &ProofSystem,
    ri_prime: Scalar,
    ri_encryption: Point<impl PointType>,
    sig_point: Point<impl PointType, impl Secrecy, impl ZeroChoice>,
    commit_base: Point,
    commit: (Point, Point),
) -> Proof {
    let enc_sub = g!(ri_encryption - { commit.1 })
        .normalize()
        .expect_nonzero("TODO: handle zero");
    let sig_sub = g!(sig_point - commit_base)
        .normalize()
        .expect_nonzero("TODO: handle zero");
    let statement = ((G.clone().mark::<Normal>(), commit.0), (sig_sub, enc_sub));
    let witness = ri_prime;

    let proof = proof_system.prove(&witness, &statement, Some(&mut rand::thread_rng()));
    proof
}

pub fn verify_eqaulity(
    proof_system: &ProofSystem,
    proof: &Proof,
    ri_encryption: Point<impl PointType>,
    sig_point: Point<impl PointType, impl Secrecy, impl ZeroChoice>,
    commit_base: Point,
    commit: (Point, Point),
) -> bool {
    let enc_sub = g!(ri_encryption - { commit.1 })
        .normalize()
        .expect_nonzero("TODO: handle zero");
    let sig_sub = g!(sig_point - commit_base)
        .normalize()
        .expect_nonzero("TODO: handle zero");
    let statement = ((G.clone().mark::<Normal>(), commit.0), (sig_sub, enc_sub));

    proof_system.verify(&statement, proof)
}
