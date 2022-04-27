use clap::Parser;
use dlc_venc_adaptor::{
    G,
    alice::*,
    bob::*,
    common::{compute_optimal_params, Params},
    oracle::Oracle,
};
use rand::Rng;
use curve25519_dalek::{scalar::Scalar, ristretto::RistrettoPoint as Point};
use serde::Serialize;
use std::time::Instant;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct CliArgs {
    /// The security parameter (how many bits of security for the overall protocol)
    #[clap(short, default_value_t = 30)]
    s: u8,
    /// The number of outcomes
    #[clap(long)]
    n_outcomes: u32,
    /// The number of oracles
    #[clap(long)]
    n_oracles: u16,
    /// The threshold of oracles that is required to attest
    #[clap(long)]
    threshold: u16,
}

fn main() -> anyhow::Result<()> {
    let args = CliArgs::parse();
    let elgamal_base = Point::random(&mut rand::thread_rng());

    let oracles = (0..args.n_oracles)
        .map(|_| Oracle::random(&mut rand::thread_rng()))
        .collect::<Vec<_>>();

    let (closed_proportion, bucket_size) =
        compute_optimal_params(args.s, args.n_outcomes as u32, args.n_oracles as u32);
    let params = Params {
        oracle_keys: oracles
            .iter()
            .map(|oracle| (oracle.public_key(), oracle.public_nonce()))
            .collect(),
        n_outcomes: args.n_outcomes,
        bucket_size,
        closed_proportion,
        elgamal_base,
        threshold: args.threshold,
    };

    let secret_sigs = (0..params.n_outcomes)
        .map(|_| Scalar::random(&mut rand::thread_rng()))
        .collect::<Vec<_>>();
    let anticipated_sigs = secret_sigs.iter().map(|s| s * &*G).collect();

    println!("Params s: {} n_oracles: {} threshold: {} n_encryptions: {} bucket_size: {} proportion_closed: {}", args.s, args.n_oracles, args.threshold, params.M(), params.bucket_size, params.closed_proportion);
    let start_round1 = Instant::now();
    let (alice, m1) = Alice1::new(&params);
    let m1_encode_len = encode_len(&m1);
    println!(
        "End round 1 elapsed: {:?} transmitted: {}",
        start_round1.elapsed(),
        m1_encode_len
    );
    let start_round2 = Instant::now();
    let (bob, m2) = Bob1::new(m1, &params)?;
    let m2_encode_len = encode_len(&m2);
    println!(
        "End round 2 elapsed: {:?} transmitted: {}",
        start_round2.elapsed(),
        m2_encode_len
    );
    let start_round3 = Instant::now();
    let m3 = alice.receive_message(m2, secret_sigs, &params)?;
    let m3_encode_len = encode_len(&m3);
    println!(
        "End round 3 elapsed: {:?} transmitted: {}",
        start_round3.elapsed(),
        m3_encode_len
    );
    let start_round4 = Instant::now();
    let bob = bob.receive_message(m3, anticipated_sigs, &params)?;
    println!("End round 4 elapsed: {:?}", start_round4.elapsed());

    let total_transmit_interactive = m1_encode_len + m2_encode_len + m3_encode_len;
    let total_transmit_non_interactive = m1_encode_len + m3_encode_len;

    println!(
        "Total elapsed: {:?} sans-preprocessing: {:?} transmitted: {} non-interactive: {}",
        start_round1.elapsed(),
        start_round2.elapsed(),
        total_transmit_interactive,
        total_transmit_non_interactive
    );

    let outcome_index = rand::thread_rng().gen_range(0, args.n_outcomes);

    let attestations = oracles
        .iter()
        .map(|oracle| oracle.attest(outcome_index))
        .collect();
    println!("got attestation");
    let scalar = bob.receive_oracle_attestation(outcome_index, attestations, &params)?;

    println!("got the secret sig {:?}", scalar);

    Ok(())
}

fn encode_len(message: &impl Serialize) -> usize {
    bincode::serde::encode_to_vec(&message, bincode::config::standard())
        .unwrap()
        .len()
}
