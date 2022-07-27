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
        let anticipated_attestations = (0..n_oracles)
            .map(|oracle_index| params.iter_anticipations(oracle_index).collect::<Vec<_>>())
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

        let bit_map: Vec<Vec<[Scalar; 2]>> = (0..n_oracles)
            .map(|_| {
                (0..params.n_outcome_bits())
                    .map(|_| {
                        [
                            Scalar::random(&mut rand::thread_rng()),
                            Scalar::random(&mut rand::thread_rng()),
                        ]
                    })
                    .collect()
            })
            .collect();

        let mut encryptions = vec![];

        let mut transcript = Transcript::new(b"dlc-dleqs");
        let mut prover = Prover::new(b"dlc-dleqs", &mut transcript);

        for (oracle_index, bits_window) in buckets
            .chunks((params.n_outcome_bits() * 2 * params.bucket_size as u32) as usize)
            .enumerate()
        {
            for (outcome_bit_index, bit_window) in bits_window
                .chunks((2 * params.bucket_size) as usize)
                .enumerate()
            {
                for (bit_value_index, bit_value_window) in
                    bit_window.chunks(params.bucket_size as usize).enumerate()
                {
                    let t = &bit_map[oracle_index][outcome_bit_index][bit_value_index];
                    let anticipated_attestation =
                        anticipated_attestations[oracle_index][outcome_bit_index][bit_value_index];

                    for (commit, (ri, ri_prime, ri_mapped)) in bit_value_window {
                        // compute the ElGamal encryption of ri_mapped
                        let ri_encryption = anticipated_attestation * ri_prime + ri_mapped;
                        // create proof ElGamal encryption value is same as commitment
                        crate::dleq::prove_eqaulity(
                            &mut prover,
                            ri_prime.clone(),
                            ri_encryption,
                            anticipated_attestation,
                            params.elgamal_base,
                            commit.C,
                        );

                        // one-time pad of the secret_share in Z_q
                        let padded_secret = ri + t;
                        encryptions.push((ri_encryption, padded_secret));
                    }
                }
            }
        }

        let proof = prover.prove_batchable();

        let secret_share_pads_by_oracle = (0..n_oracles)
            .map(|oracle_index| {
                let secret_share_pads = compute_pads(&bit_map[oracle_index][..]);

                secret_share_pads
                    .into_iter()
                    .enumerate()
                    .take(params.n_outcomes as usize)
                    .map(|(outcome_index, pad)| {
                        let scalar_poly = &scalar_polys[outcome_index];
                        let secret_share = scalar_poly.eval((oracle_index + 1) as u32);
                        pad + secret_share
                    })
                    .collect()
            })
            .collect();

        let bit_map_images = bit_map
            .iter()
            .map(|oracle_bits| {
                oracle_bits
                    .iter()
                    .map(|oracle_bit| [&oracle_bit[0] * &*G, &oracle_bit[1] * &*G])
                    .collect()
            })
            .collect();

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
            bit_map_images,
            secret_share_pads_by_oracle,
        })
    }
}

fn compute_pads(pads: &[[Scalar; 2]]) -> Vec<Scalar> {
    _compute_pads(pads.len() - 1, Scalar::zero(), pads)
}

fn _compute_pads(cur_bit: usize, acc: Scalar, pads: &[[Scalar; 2]]) -> Vec<Scalar> {
    let zero = acc + { &pads[cur_bit][0] };
    let one = acc + { &pads[cur_bit][1] };

    if cur_bit == 0 {
        vec![zero, one]
    } else {
        let mut children = _compute_pads(cur_bit - 1, zero, pads);
        children.extend(_compute_pads(cur_bit - 1, one, pads));
        children
    }
}
