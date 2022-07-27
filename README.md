# Sketch of DLCs using cut-and-choose verifiable encryption

**This implementation uses Ristretto and [zkp](https://docs.rs/zkp/0.8.0/zkp/)**

As of 27-07-22 it uses the bit decomposition technique from the new revision.

DLCs via verifiable encryption with `r*i + x` as the oracle's attestation scheme where `r` is a per event nonce, `i` is the index of the outcome from 1..n and `x` the oracle's static secret key.

In the protocol "Alice" verifiably encrypts a list of secret scalar's to their corresponding anticipated oracle attestation points such that when the oracle attests to an outcome "Bob" can decrypt it.

important points:

1. I implemented the cut-and-choose interactively (not via Fiat-Shamir) but this could easily be changed.

## Run it

Here's how to run it with `30` bits of security for the overall protocol 1024 outcomes and a threshold of 3/5 oracles:

```
cargo run --release -- -s 30 --n-outcomes 1024 --threshold 3 --n-oracles 5
```

