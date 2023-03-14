# Verfifiable encryption benchmark

**This implementation uses Ristretto and [zkp](https://docs.rs/zkp/0.8.0/zkp/)**

I created this branch to benchmark the actual verifiable encryption we developed for *[Cryptographic Oracle-Based Conditional Payments]* without all the DLC specific stuff. This benchmarks pure batch cut and choose verifiable encryption of a list of ristretto scalars to a list of ristretto points (public keys).

The protocol is implemented as an interactive protocol but the challenge that "bob" gives for the cut-and-choose opening and closing can be implemented using a 128-bit hash function instead.

This code is for benchmarking only.

## Run it

Shows how long it takes to to make 100 verifiable encryptions at the 128 bit security level.
The output still takes the form of a interactive protocol but you can imagine Bob's first activation to be replaced with calling a hash function.

```
cargo run --release -- -s 128 --n-encryptions 100
```


[Cryptographic Oracle-Based Conditional Payments]: https://eprint.iacr.org/2022/499.pdf
