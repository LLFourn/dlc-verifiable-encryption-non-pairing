use clap::Parser;
use curve25519_dalek::{ristretto::RistrettoPoint as Point, scalar::Scalar};
use dlc_venc_adaptor::{
    alice::*,
    bob::*,
    common::{compute_optimal_params, Params},
    G,
};
use serde::Serialize;
use std::time::Instant;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct CliArgs {
    /// The security parameter (how many bits of security for the overall protocol)
    #[clap(short, default_value_t = 30)]
    s: u8,
    /// The number of encryptions
    #[clap(long, short)]
    n_encryptions: usize,
}

fn main() -> anyhow::Result<()> {
    let args = CliArgs::parse();
    let elgamal_base = Point::random(&mut rand::thread_rng());

    let (closed_proportion, bucket_size) = compute_optimal_params(args.s, args.n_encryptions);
    let params = Params {
        bucket_size,
        closed_proportion,
        elgamal_base,
        n_encryptions: args.n_encryptions,
    };

    let secrets_to_be_encrypted = (0..params.n_encryptions)
        .map(|_| Scalar::random(&mut rand::thread_rng()))
        .collect::<Vec<_>>();
    let images_of_secrets_to_be_encrypted: Vec<_> =
        secrets_to_be_encrypted.iter().map(|s| s * &*G).collect();
    let decryption_keys = (0..params.n_encryptions)
        .map(|_| Scalar::random(&mut rand::thread_rng()))
        .collect::<Vec<_>>();
    let public_encryption_keys: Vec<_> = decryption_keys.iter().map(|s| s * &*G).collect();

    println!("Params s: {} n_encryptions: {}, n_elgamal_encryptions: {} bucket_size: {} proportion_closed: {}", args.s, args.n_encryptions, params.M(), params.bucket_size, params.closed_proportion);
    let start_round1 = Instant::now();
    let (alice, m1) = Alice1::new(&params);
    let m1_encode_len = encode_len(&m1);
    println!(
        "End Alice 1 elapsed: {:?} transmitted: {}",
        start_round1.elapsed(),
        m1_encode_len
    );
    let start_round2 = Instant::now();
    let (bob, m2) = Bob1::new(m1, &params)?;
    let m2_encode_len = encode_len(&m2);
    println!(
        "End Bob   1 elapsed: {:?} transmitted: {}",
        start_round2.elapsed(),
        m2_encode_len
    );
    let start_round3 = Instant::now();
    let m3 = alice.receive_message(
        m2,
        &secrets_to_be_encrypted,
        &public_encryption_keys,
        &params,
    )?;
    let m3_encode_len = encode_len(&m3);
    println!(
        "End Alice 2 elapsed: {:?} transmitted: {}",
        start_round3.elapsed(),
        m3_encode_len
    );
    let start_round4 = Instant::now();
    let bob = bob.receive_message(
        m3,
        &images_of_secrets_to_be_encrypted,
        &public_encryption_keys,
        &params,
    )?;
    println!("End Bob   2 elapsed: {:?}", start_round4.elapsed());

    let total_transmit_interactive = m1_encode_len + m2_encode_len + m3_encode_len;
    let total_transmit_non_interactive = m1_encode_len + m3_encode_len;

    println!(
        "Total elapsed: {:?} sans-preprocessing: {:?} transmitted: {} non-interactive: {}",
        start_round1.elapsed(),
        start_round2.elapsed(),
        total_transmit_interactive,
        total_transmit_non_interactive
    );

    for (i, decryption_key) in decryption_keys.into_iter().enumerate() {
        let decryption = bob.decrypt_bucket_with_key(
            i,
            decryption_key,
            images_of_secrets_to_be_encrypted[i],
            &params,
        );
        assert_eq!(
            decryption.expect("decryption failed"),
            secrets_to_be_encrypted[i]
        );
    }

    println!("encryptions were all decrypted correctly");

    Ok(())
}

fn encode_len(message: &impl Serialize) -> usize {
    bincode::serde::encode_to_vec(&message, bincode::config::standard())
        .unwrap()
        .len()
}
