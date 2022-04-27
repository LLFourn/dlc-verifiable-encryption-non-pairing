use crate::{common::Params, messages::*, G};
use anyhow::anyhow;
use rand::{prelude::SliceRandom, RngCore};
use curve25519_dalek::{scalar::Scalar, ristretto::RistrettoPoint as Point};
use zkp::{toolbox::{verifier::Verifier}, Transcript};

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
        mut message: Message3,
        sig_images: Vec<Point>,
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
        let mut anticipated_attestations = (0..n_oracles)
            .map(|oracle_index| params.iter_anticipations(oracle_index))
            .collect::<Vec<_>>();
        let mut outcome_buckets = vec![];


        let mut transcript = Transcript::new(b"dlc-dleqs");
        let mut verifier = Verifier::new(b"dlc-dleqs", &mut transcript);

        for (outcome_index, buckets) in buckets
            .chunks(params.bucket_size as usize * n_oracles)
            .enumerate()
        {
            let sig_image = sig_images[outcome_index];
            let mut oracle_buckets = vec![];
            let poly = &mut message.polys[outcome_index];
            poly.push_front(sig_image);
            for (oracle_index, bucket) in buckets.chunks(params.bucket_size as usize).enumerate() {
                let anticipated_attestation =
                    anticipated_attestations[oracle_index].next().unwrap();
                let mut oracle_bucket = vec![];
                let sig_share_image = poly.eval((oracle_index + 1) as u32);
                for (commit, (encryption, padded_sig)) in bucket {
                    crate::dleq::verify_eqaulity(
                        &mut verifier,
                        *encryption,
                        anticipated_attestation,
                        params.elgamal_base,
                        commit.C,
                    );

                    if sig_share_image + commit.R != padded_sig * &*G {
                        return Err(anyhow!("padded sig wasn't valid"));
                    }

                    oracle_bucket.push(((commit.C.0, *encryption), padded_sig.clone(), commit.pad));
                }
                oracle_buckets.push((oracle_bucket, sig_share_image))
            }
            outcome_buckets.push((oracle_buckets, sig_image));
        }

        if verifier.verify_batchable(&message.proof).is_err() {
            return Err(anyhow!(
                            "proof of equality between ciphertext and commitment was invalid"
                        ));
        }


        Ok(Bob2 { outcome_buckets })
    }
}

pub struct Bob2 {
    outcome_buckets: Vec<(
        // for every outcome:
        // 1. A list of entries corresponding to oracles
        Vec<(
            // For every oracle:
            // 1. A list of encryptions (all encrypting the same signature share)
            Vec<((Point, Point), Scalar, [u8; 32])>,
            // 2. The image of the signature share that will be encrypted
            Point,
        )>,
        // 2. The sig image that should be unlocked iwth this outcome
        Point,
    )>,
}

impl Bob2 {
    pub fn receive_oracle_attestation(
        mut self,
        outcome_index: u32,
        attestations: Vec<Scalar>,
        params: &Params,
    ) -> anyhow::Result<Scalar> {
        let (outcome_bucket, sig_image) = self.outcome_buckets.remove(outcome_index as usize);
        let mut sig_shares = vec![];
        for (oracle_index, ((oracle_bucket, sig_share_image), attestation)) in
            outcome_bucket.into_iter().zip(attestations).enumerate()
        {
            if &attestation * &*G != params.anticipate_at_index(oracle_index, outcome_index) {
                eprintln!("attestation didn't match anticipated attestation");
                continue;
            }

            for (encryption, padded_sig_share, pad) in oracle_bucket {
                let ri_mapped = encryption.1 - attestation * encryption.0;
                let ri = crate::common::map_G_to_Zq(ri_mapped, pad);
                let sig_share = padded_sig_share - ri;
                let got_sig_share_image = &sig_share * &*G;
                if got_sig_share_image == sig_share_image {
                    sig_shares.push((
                        Scalar::from(oracle_index as u32 + 1),
                        sig_share,
                    ));
                    break;
                } else {
                    eprintln!(
                        "Found a malicious encryption. Expecting {:?} got {:?}",
                        sig_share_image, got_sig_share_image
                    );
                }

            }
        }

        if sig_shares.len() >= params.threshold as usize {
            let shares = &sig_shares[0..params.threshold as usize];

            let secret_sig = shares.iter().fold(Scalar::from(0u32), |acc, (x_j, y_j)| {
                let x_ms = shares
                    .iter()
                    .map(|(x_m, _)| x_m)
                    .filter(|x_m| x_m != &x_j)
                    .collect::<Vec<_>>();
                let (num, denom) = x_ms.iter().fold((Scalar::from(1u32), Scalar::from(1u32)), |(acc_n, acc_d), x_m| {
                    (
                        acc_n * *x_m,
                        acc_d * (*x_m - x_j),
                    )
                });
                let lagrange_coeff = num * { denom.invert() };
                acc + lagrange_coeff * y_j
            });

            if &secret_sig * &*G != sig_image {
                return Err(anyhow!("the sig we recovered"));
            }

            Ok(secret_sig)
        } else {
            Err(anyhow!("not enough shares to reconstruct secret!"))
        }
    }
}
