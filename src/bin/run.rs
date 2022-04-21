use dlc_venc_adaptor::{alice::*, bob::*, common::Params, oracle::Oracle};
use secp256kfun::{g, s, Point, Scalar, G};

fn main() -> anyhow::Result<()> {
    let oracle_sk = s!(42);
    let oracle = Oracle::new(oracle_sk);
    let oracle_key = oracle.public_key();
    let elgamal_base = Point::random(&mut rand::thread_rng());
    let oracle_secret_nonce = s!(84);
    let oracle_nonce = g!(oracle_secret_nonce * G).normalize();
    // let params = Params {
    //     oracle_key,
    //     n_outcomes: 2,
    //     event_id: "test".to_string(),
    //     bucket_size: 2,
    //     closed_proportion: 0.5,
    //     elgamal_base,
    // };

    let params = Params {
        oracle_key,
        oracle_nonce,
        n_outcomes: 1024,
        bucket_size: 6,
        closed_proportion: 0.85,
        elgamal_base,
    };

    println!("alice round 1");
    let (alice, m1) = Alice1::new(&params);
    println!("bob round 2");
    let (bob, m2) = Bob1::new(m1, &params)?;
    let secret_sigs = (0..params.n_outcomes)
        .map(|_| Scalar::random(&mut rand::thread_rng()))
        .collect::<Vec<_>>();
    let anticipated_sigs = secret_sigs.iter().map(|s| g!(s * G).normalize()).collect();
    println!("alice round 3");
    let m3 = alice.receive_message(m2, secret_sigs, &params)?;
    println!("bob round 4");
    let bob = bob.receive_message(m3, anticipated_sigs, &params)?;

    let attestation = oracle.attest(oracle_secret_nonce, 2);
    println!("attestation");
    let scalar = bob.receive_oracle_attestation(2, attestation, &params)?;

    println!("got the secret sig {}", scalar);

    Ok(())
}
