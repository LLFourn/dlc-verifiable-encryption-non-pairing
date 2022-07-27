use crate::{common::Params, messages::*, G};
use anyhow::anyhow;
use curve25519_dalek::{ristretto::RistrettoPoint as Point, scalar::Scalar};
use rand::{prelude::SliceRandom, RngCore};
use zkp::{toolbox::verifier::Verifier, Transcript};

pub struct Bob1 {
    commits: Vec<Commit>,
    message2: Message2,
}

impl Bob1 {
    pub fn new(message: Message1, params: &Params) -> anyhow::Result<(Bob1, Message2)> {
        if message.commits.len() != params.M() {
            return Err(anyhow!("Alice sent wrong number of commitments"));
        }
        let message2 = Self::gen_message2(&message.commits, params, &mut rand::thread_rng());
        Ok((
            Bob1 {
                commits: message.commits,
                message2: message2.clone(),
            },
            message2,
        ))
    }

    pub fn gen_message2(commits: &[Commit], params: &Params, rng: &mut impl RngCore) -> Message2 {
        let indexes = (0..commits.len()).collect::<Vec<_>>();
        let openings = indexes
            .choose_multiple(rng, params.num_openings())
            .cloned()
            .collect();

        let mut bucket_mapping = (0..params.NB()).collect::<Vec<_>>();
        bucket_mapping.shuffle(rng);

        Message2 {
            bucket_mapping,
            openings,
        }
    }

    pub fn receive_message(
        self,
        message: Message3,
        outcome_images: Vec<Point>,
        params: &Params,
    ) -> anyhow::Result<Bob2> {
        let Bob1 {
            mut commits,
            message2,
        } = self;
        let mut opened = vec![];
        let mut i = 0;

        commits.retain(|commit| {
            let open_it = message2.openings.contains(&i);
            if open_it {
                opened.push(commit.clone());
            }
            i += 1;
            !open_it
        });

        for (commit, opening) in opened.iter().zip(message.openings.iter()) {
            let ri_prime = opening;
            let Ri_prime = ri_prime * &*G;
            if Ri_prime != commit.C.0 {
                return Err(anyhow!("decommitment was wrong"));
            }
            let ri_mapped = commit.C.1 - ri_prime * params.elgamal_base;
            let ri = crate::common::map_G_to_Zq(ri_mapped, commit.pad);

            if &ri * &*G != commit.R {
                return Err(anyhow!(
                    "decommitment of chain scalar didn't match chain point"
                ));
            }
        }

        let mut buckets = Vec::with_capacity(params.NB());

        for (from, encryption) in message2.bucket_mapping.into_iter().zip(message.encryptions) {
            buckets.push((commits[from], encryption));
        }

        let n_oracles = params.oracle_keys.len();
        let anticipated_attestations = (0..n_oracles)
            .map(|oracle_index| params.iter_anticipations(oracle_index).collect::<Vec<_>>())
            .collect::<Vec<_>>();
        let mut bit_map_encryptions = vec![];

        let mut transcript = Transcript::new(b"dlc-dleqs");
        let mut verifier = Verifier::new(b"dlc-dleqs", &mut transcript);

        for (oracle_index, bits_window) in buckets
            .chunks((params.n_outcome_bits() * 2 * params.bucket_size as u32) as usize)
            .enumerate()
        {
            let mut bits: Vec<[_; 2]> = vec![];
            for (bit_index, bit_window) in bits_window
                .chunks((2 * params.bucket_size) as usize)
                .enumerate()
            {
                let mut bit_values = vec![];
                for (bit_value_index, bit_value_window) in
                    bit_window.chunks((params.bucket_size) as usize).enumerate()
                {
                    let T = message.bit_map_images[oracle_index][bit_index][bit_value_index];
                    let anticipated_attestation =
                        anticipated_attestations[oracle_index][bit_index][bit_value_index];

                    let mut bit_value_bucket = vec![];
                    for (commit, (encryption, padded_T)) in bit_value_window {
                        crate::dleq::verify_eqaulity(
                            &mut verifier,
                            *encryption,
                            anticipated_attestation,
                            params.elgamal_base,
                            commit.C,
                        );

                        if T + commit.R != padded_T * &*G {
                            return Err(anyhow!("padded bit_map wasn't valid"));
                        }

                        bit_value_bucket.push(((commit.C.0, *encryption), *padded_T, commit.pad));
                    }
                    bit_values.push((bit_value_bucket, T))
                }
                bits.push(bit_values.try_into().unwrap());
            }
            bit_map_encryptions.push(bits);
        }

        if verifier.verify_batchable(&message.proof).is_err() {
            return Err(anyhow!(
                "proof of equality between ciphertext and commitment was invalid"
            ));
        }

        Ok(Bob2 {
            bit_map_encryptions,
            secret_share_pads_by_oracle: message.secret_share_pads_by_oracle,
            outcome_images,
        })
    }
}

pub struct Bob2 {
    // For every oracle
    bit_map_encryptions: Vec<
        // For every outcome bit
        Vec<
            // two bit values
            [(
                // a bucket of encryptions
                Vec<((Point, Point), Scalar, [u8; 32])>,
                // The image of the bit map that is encrypted
                Point,
            ); 2],
        >,
    >,
    // The image of the secret that should be revealed for each outcome
    secret_share_pads_by_oracle: Vec<Vec<Scalar>>,
    outcome_images: Vec<Point>,
}

impl Bob2 {
    pub fn receive_oracle_attestation(
        self,
        outcome_index: u32,
        attestations: Vec<Vec<Scalar>>,
        params: &Params,
    ) -> anyhow::Result<Scalar> {
        let outcome_bits = crate::common::to_bits(outcome_index, params.n_outcome_bits() as usize);
        let mut secret_shares = vec![];
        for (oracle_index, bit_attestations) in attestations.into_iter().enumerate() {
            assert_eq!(
                outcome_bits.len(),
                bit_attestations.len(),
                "attestation for oracle didn't have the right number of signatures"
            );

            let bit_map_pads = outcome_bits
                .iter()
                .zip(bit_attestations)
                .enumerate()
                .map(|(bit_index, (bit_value, bit_attestation))| {
                    if &bit_attestation * &*G
                        != params.anticipate_at_index(oracle_index, bit_index as u32, *bit_value)
                    {
                        eprintln!("attestation didn't match anticipated attestation");
                        return None;
                    }

                    let (outcome_bit_bucket, expected_bit_map_image) =
                        &self.bit_map_encryptions[oracle_index][bit_index][*bit_value as usize];
                    outcome_bit_bucket.iter().find_map(
                        |(encryption, padded_bit_map_secret, pad)| {
                            let ri_mapped = encryption.1 - bit_attestation * encryption.0;
                            let ri = crate::common::map_G_to_Zq(ri_mapped, *pad);
                            let bit_map_secret = padded_bit_map_secret - ri;
                            let got_bit_map_image = &bit_map_secret * &*G;
                            if &got_bit_map_image == expected_bit_map_image {
                                Some(bit_map_secret)
                            } else {
                                eprintln!(
                                    "we didn't decrypt what was expected -- ignoring that share"
                                );
                                None
                            }
                        },
                    )
                })
                .collect::<Option<Vec<_>>>();

            let secret_share_pad = match bit_map_pads {
                Some(bit_map_pads) => bit_map_pads
                    .into_iter()
                    .fold(Scalar::zero(), |acc, pad| acc + pad),
                None => continue,
            };

            let secret_share = self.secret_share_pads_by_oracle[oracle_index]
                [outcome_index as usize]
                - secret_share_pad;

            secret_shares.push((Scalar::from(oracle_index as u32 + 1), secret_share));
        }

        if secret_shares.len() >= params.threshold as usize {
            let shares = &secret_shares[0..params.threshold as usize];

            let secret = shares.iter().fold(Scalar::from(0u32), |acc, (x_j, y_j)| {
                let x_ms = shares
                    .iter()
                    .map(|(x_m, _)| x_m)
                    .filter(|x_m| x_m != &x_j)
                    .collect::<Vec<_>>();
                let (num, denom) = x_ms.iter().fold(
                    (Scalar::from(1u32), Scalar::from(1u32)),
                    |(acc_n, acc_d), x_m| (acc_n * *x_m, acc_d * (*x_m - x_j)),
                );
                let lagrange_coeff = num * { denom.invert() };
                acc + lagrange_coeff * y_j
            });

            if &secret * &*G != self.outcome_images[outcome_index as usize] {
                return Err(anyhow!("the secret we recovered was wrong"));
            }

            Ok(secret)
        } else {
            Err(anyhow!("not enough shares to reconstruct secret!"))
        }
    }
}
