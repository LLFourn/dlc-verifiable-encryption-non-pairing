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
        images_of_secrets_to_be_encrypted: &[Point],
        public_encryption_keys: &[Point],
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

        let mut verifiably_encrypted = vec![];

        let mut transcript = Transcript::new(b"venc-dleqs");
        let mut verifier = Verifier::new(b"venc-dleqs", &mut transcript);

        for (ve_index, buckets) in buckets.chunks(params.bucket_size as usize).enumerate() {
            let secret_image = images_of_secrets_to_be_encrypted[ve_index];
            let mut bucket_of_encryptions = vec![];
            let public_encryption_key = public_encryption_keys[ve_index];
            for (commit, (ri_encryption, padded_secret)) in buckets {
                crate::dleq::verify_eqaulity(
                    &mut verifier,
                    *ri_encryption,
                    public_encryption_key,
                    params.elgamal_base,
                    commit.C,
                );

                if secret_image + commit.R != padded_secret * &*G {
                    return Err(anyhow!("padded secret wasn't valid"));
                }

                bucket_of_encryptions.push((
                    (commit.C.0, *ri_encryption),
                    *padded_secret,
                    commit.pad,
                ));
            }
            verifiably_encrypted.push(bucket_of_encryptions);
        }

        if verifier.verify_batchable(&message.proof).is_err() {
            return Err(anyhow!(
                "proof of equality between ciphertext and commitment was invalid"
            ));
        }

        Ok(Bob2 {
            verifiably_encrypted,
        })
    }
}

pub struct Bob2 {
    verifiably_encrypted: Vec<Vec<((Point, Point), Scalar, [u8; 32])>>,
}

impl Bob2 {
    pub fn decrypt_bucket_with_key(
        &self,
        ve_index: usize,
        decryption_key: Scalar,
        image_that_should_be_encrypted: Point,
        _params: &Params,
    ) -> anyhow::Result<Scalar> {
        let bucket = self.verifiably_encrypted[ve_index].clone();

        for (encryption, padded_secret, pad) in bucket {
            let ri_mapped = encryption.1 - decryption_key * encryption.0;
            let ri = crate::common::map_G_to_Zq(ri_mapped, pad);
            let preimage = padded_secret - ri;
            let got_image = &preimage * &*G;
            if got_image == image_that_should_be_encrypted {
                return Ok(preimage);
            } else {
                eprintln!(
                    "Found a malicious encryption. Expecting {:?} got {:?}",
                    image_that_should_be_encrypted.compress(),
                    got_image.compress()
                );
            }
        }

        Err(anyhow!("the encryption was malicious"))
    }
}
