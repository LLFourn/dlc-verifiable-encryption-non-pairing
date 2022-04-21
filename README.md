# Sketch of DLCs using cut-and-choose verifiable encryption (prime-order group edition)

important points:

1. The parameters I took are from https://eprint.iacr.org/2014/667.pdf Appendix A table 2 (number of outcomes 1024, bucket_size: 6, proportion of balls not to break: 0.85).
2. I implemented the cut-and-choose interactively (not via Fiat-Shamir) but this could easily be changed.


## Run it

```
cargo run --release
```
