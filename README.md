# Sketch of DLCs using cut-and-choose verifiable encryption (prime-order group edition)

important points:

1. The parameters I took are from https://eprint.iacr.org/2014/667.pdf Appendix A table 2 (number of outcomes 1024, bucket_size: 6, proportion of balls not to break: 0.85).
2. I implemented the cut-and-choose interactively (not via Fiat-Shamir) but this could easily be changed.
3. I don't actually use adaptor signature per se. Rather we are just one-time padding scalars which are passed in. In reality these could indeed be Schnorr signatures on a particular message and R values.

## Run it

Here's how to run it with `30` bits of security for the overall protocol 1024 outcomes and a threshold of 3/5 oracles:

```
cargo run --release -- -s 30 --n-outcomes 1024 --threshold 3 --n-oracles 5
```
