use crate::common::Params;
use crate::messages::*;
use anyhow::anyhow;
use curve25519_dalek::{scalar::Scalar, ristretto::RistrettoPoint as Point};
use crate::G;
use zkp::{toolbox::prover::Prover, Transcript};

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

                let Ri = &ri * &*G;
                let ri_prime = Scalar::random(&mut rand::thread_rng());
                let C_i = (
                    &ri_prime * &*G,
                   ri_prime * params.elgamal_base + ri_mapped
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

        let mut buckets = Vec::with_capacity(params.NB());

        for from in message.bucket_mapping.into_iter() {
            buckets.push((commits[from], &secrets[from]));
        }

        let n_oracles = params.oracle_keys.len();
        let mut anticipated_attestations = (0..n_oracles)
            .map(|oracle_index| params.iter_anticipations(oracle_index))
            .collect::<Vec<_>>();

        let scalar_polys = (0..params.n_outcomes)
            .map(|outcome_index| {
                let secret_sig = secret_sigs[outcome_index as usize].clone();
                let mut poly = crate::poly::ScalarPoly::random(
                    (params.threshold - 1) as usize,
                    &mut rand::thread_rng(),
                );
                poly.push_front(secret_sig);
                poly
            })
            .collect::<Vec<_>>();

        let mut encryptions = vec![];

        let mut transcript = Transcript::new(b"dlc-dleqs");
        let mut prover = Prover::new(b"dlc-dleqs", &mut transcript);

        for (outcome_index, buckets) in buckets
            .chunks(params.bucket_size as usize * n_oracles)
            .enumerate()
        {
            let scalar_poly = &scalar_polys[outcome_index];
            for (oracle_index, bucket) in buckets.chunks(params.bucket_size as usize).enumerate() {
                let anticipated_attestation =
                    anticipated_attestations[oracle_index].next().unwrap();
                let secret_sig_share = scalar_poly.eval((oracle_index + 1) as u32);
                for (commit, (ri, ri_prime, ri_mapped)) in bucket {
                    // compute the ElGamal encryption to the signature of ri_mapped
                    let ri_encryption = ri_prime * anticipated_attestation + ri_mapped;
                    // create proof ElGamal encryption value is same as commitment

                    crate::dleq::prove_eqaulity(
                        &mut prover,
                        ri_prime.clone(),
                        ri_encryption,
                        anticipated_attestation,
                        params.elgamal_base,
                        commit.C,
                    );

                    // assert!(crate::dleq::verify_eqaulity(&proof_system, &proof, ri_encryption, sig_point, params.elgamal_base, commit.C));
                    // one-time pad of the signature in Z_q
                    let padded_secret = ri + secret_sig_share;
                    encryptions.push((ri_encryption, padded_secret));
                }
            }
        }

        let proof = prover.prove_batchable();

        let polys = scalar_polys
            .into_iter()
            .map(|mut poly| {
                poly.pop_front();
                poly.to_point_poly()
            })
            .collect();

        Ok(Message3 {
            proof,
            encryptions,
            openings,
            polys,
        })
    }
}
