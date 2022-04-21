use crate::common::Params;
use crate::messages::*;
use anyhow::anyhow;
use secp256kfun::{g, s, Point, Scalar, G};
pub struct Alice1 {
    secrets: Vec<(Scalar, Scalar, Point)>,
    commits: Vec<Commit>,
}

impl Alice1 {
    pub fn new(params: &Params) -> (Alice1, Message1) {
        let (commits, secrets) = (0..params.M())
            .map(|_| {
                let (padi, ri, ri_mapped) = {
                    let ri = Scalar::random(&mut rand::thread_rng());
                    let (ri_mapped, padi) = crate::common::map_Zq_to_G(&ri);
                    (padi, ri, ri_mapped)
                };

                let Ri = g!(ri * G).normalize();
                let ri_prime = Scalar::random(&mut rand::thread_rng());
                let C_i = (
                    g!(ri_prime * G).normalize(),
                    g!(ri_prime * params.elgamal_base + ri_mapped)
                        .normalize()
                        .expect_nonzero("computationally unreachable"),
                );

                (
                    Commit {
                        C: C_i,
                        R: Ri,
                        pad: padi,
                    },
                    (ri, ri_prime, ri_mapped),
                )
            })
            .unzip();

        let message = Message1 {
            commits: Clone::clone(&commits),
        };

        (
            Alice1 {
                secrets,
                commits: commits.clone(),
            },
            message,
        )
    }

    pub fn receive_message(
        self,
        message: Message2,
        secret_sigs: Vec<Scalar>,
        params: &Params,
    ) -> anyhow::Result<Message3> {
        let NB = params.NB();
        if let Some(bad_index) = message.bucket_mapping.iter().find(|map| **map >= NB) {
            return Err(anyhow!(
                "bucket was mapped to {} which is outside of range 0..{}",
                bad_index,
                NB
            ));
        }

        if message.openings.len() != params.num_openings() {
            return Err(anyhow!(
                "wrong number of openings requested. Expected {} got {}",
                params.num_openings(),
                message.openings.len()
            ));
        }

        let Alice1 {
            mut secrets,
            mut commits,
        } = self;

        let mut i = 0;
        commits.retain(|_| {
            let open_it = message.openings.contains(&i);
            i += 1;
            !open_it
        });

        let mut i = 0;
        let mut openings = vec![];
        secrets.retain(|secret| {
            let open_it = message.openings.contains(&i);
            i += 1;
            if open_it {
                openings.push(secret.1.clone());
            }
            !open_it
        });

        let mut buckets = Vec::with_capacity(params.bucket_size * params.n_outcomes);

        for from in message.bucket_mapping.into_iter() {
            buckets.push((commits[from], &secrets[from]));
        }

        let proof_system = crate::dleq::ProofSystem::default();
        let mut anticipated_points = params.iter_anticipations();

        let encryptions = buckets
            .chunks(params.bucket_size)
            .enumerate()
            .flat_map(|(bucket_index, bucket)| {
                let sig_point = anticipated_points.next().unwrap();
                let secret_sig = secret_sigs[bucket_index].clone();
                let mut encryption_bucket = vec![];
                for (commit, (ri, ri_prime, ri_mapped)) in bucket {
                    // compute the ElGamal encryption to the signature of ri_mapped
                    let ri_encryption = g!(ri_prime * sig_point + ri_mapped)
                        .expect_nonzero("computationally unreachable")
                        .normalize();
                    // create proof ElGamal encryption value is same as commitment

                    let proof = crate::dleq::prove_eqaulity(
                        &proof_system,
                        ri_prime.clone(),
                        ri_encryption,
                        sig_point,
                        params.elgamal_base,
                        commit.C,
                    );

                    // assert!(crate::dleq::verify_eqaulity(&proof_system, &proof, ri_encryption, sig_point, params.elgamal_base, commit.C));
                    // one-time pad of the signature in Z_q
                    let padded_secret = s!(ri + secret_sig);
                    encryption_bucket.push((proof, ri_encryption, padded_secret));
                }
                encryption_bucket.into_iter()
            })
            .collect();

        Ok(Message3 {
            encryptions,
            openings,
        })
    }
}
