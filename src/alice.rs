use crate::common::Params;
use crate::messages::*;
use crate::G;
use anyhow::anyhow;
use curve25519_dalek::{ristretto::RistrettoPoint as Point, scalar::Scalar};
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
                let C_i = (&ri_prime * &*G, ri_prime * params.elgamal_base + ri_mapped);
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
        secrets_to_be_encrpted: &[Scalar],
        public_encryption_keys: &[Point],
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

        let mut encryptions = vec![];

        let mut transcript = Transcript::new(b"venc-dleqs");
        let mut prover = Prover::new(b"venc-dleqs", &mut transcript);

        for (ve_index, bucket) in buckets.chunks(params.bucket_size as usize).enumerate() {
            let public_encryption_key = public_encryption_keys[ve_index];
            for (commit, (ri, ri_prime, ri_mapped)) in bucket {
                // ElGamal encryption of ri_mapped
                let ri_encryption = ri_prime * public_encryption_key + ri_mapped;
                // create proof ElGamal encryption value is same as commitment
                crate::dleq::prove_eqaulity(
                    &mut prover,
                    ri_prime.clone(),
                    ri_encryption,
                    public_encryption_key,
                    params.elgamal_base,
                    commit.C,
                );

                // one-time pad of the secret in Z_q
                let padded_secret = ri + secrets_to_be_encrpted[ve_index];
                encryptions.push((ri_encryption, padded_secret));
            }
        }

        let proof = prover.prove_batchable();

        Ok(Message3 {
            proof,
            encryptions,
            openings,
        })
    }
}
