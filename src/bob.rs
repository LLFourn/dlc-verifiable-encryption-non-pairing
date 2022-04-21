use crate::{common::Params, messages::*};
use anyhow::anyhow;
use rand::{prelude::SliceRandom, RngCore};
use secp256kfun::{g, marker::*, s, Point, Scalar, G};

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
        anticipated_sigs: Vec<Point>,
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
            let Ri_prime = g!(ri_prime * G);
            if Ri_prime != commit.C.0 {
                return Err(anyhow!("decommitment was wrong"));
            }
            let ri_mapped = g!({ commit.C.1 } - ri_prime * params.elgamal_base)
                .normalize()
                .mark::<NonZero>()
                .ok_or(anyhow!("encrypted ri was identity"))?;
            let ri = crate::common::map_G_to_Zq(ri_mapped, commit.pad);

            if g!(ri * G) != commit.R {
                return Err(anyhow!(
                    "decommitment of chain scalar didn't match chain point"
                ));
            }
        }

        let mut buckets = Vec::with_capacity(params.bucket_size * params.n_outcomes);

        for (from, encryption) in message2.bucket_mapping.into_iter().zip(message.encryptions) {
            buckets.push((commits[from], encryption));
        }

        let proof_system = crate::dleq::ProofSystem::default();
        let mut anticipated_points = params.iter_anticipations();
        let mut encryption_buckets = vec![];

        for (bucket_index, bucket) in buckets.chunks(params.bucket_size).enumerate() {
            let sig_point = anticipated_points.next().unwrap();
            let mut encryption_bucket = vec![];
            let anticipated_sig = &anticipated_sigs[bucket_index];
            for (commit, (proof, encryption, padded_sig)) in bucket {
                if !crate::dleq::verify_eqaulity(
                    &proof_system,
                    proof,
                    *encryption,
                    sig_point,
                    params.elgamal_base,
                    commit.C,
                ) {
                    return Err(anyhow!(
                        "proof of equality between ciphertext and commitment was invalid"
                    ));
                }

                if g!(anticipated_sig + commit.R) != g!(padded_sig * G) {
                    return Err(anyhow!("padded sig wasn't valid"));
                }

                encryption_bucket.push(((commit.C.0, *encryption), padded_sig.clone(), commit.pad));
            }
            encryption_buckets.push((encryption_bucket, *anticipated_sig));
        }

        Ok(Bob2 { encryption_buckets })
    }
}

pub struct Bob2 {
    encryption_buckets: Vec<(Vec<((Point, Point), Scalar<Secret, Zero>, [u8; 32])>, Point)>,
}

impl Bob2 {
    pub fn receive_oracle_attestation(
        mut self,
        index: usize,
        attestation: Scalar<Public, Zero>,
        params: &Params,
    ) -> anyhow::Result<Scalar<Public, Zero>> {
        let bucket = self.encryption_buckets.remove(index);
        if g!(attestation * G) != params.anticipate_at_index(index as u32) {
            return Err(anyhow!("attestation didn't match anticipated attestation"));
        }
        let anticipated_sig = &bucket.1;
        let sig = bucket.0.iter().find_map(|(encryption, padded_sig, pad)| {
            // let ri_mapped = &encryption.1 - e(&attestation, &encryption.0);
            let ri_mapped = g!({ encryption.1 } - attestation * { encryption.0 })
                .normalize()
                .mark::<NonZero>()?;
            let ri = crate::common::map_G_to_Zq(ri_mapped, *pad);
            let sig = s!(padded_sig - ri).mark::<Public>();
            if &g!(sig * G) == anticipated_sig {
                Some(sig)
            } else {
                None
            }
        });

        sig.ok_or(anyhow!("all the ciphertexts were malicious!"))
    }
}