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


## Benches

cpu:

```
AMD® Ryzen 7 pro 4750u
```

### Varying the security parameter

command:

``` sh
for i in 20 30 40 128; do echo "s=$i"; cargo run --release -- -s $i --n-outcomes 1024 --threshold 1 --n-oracles 1 2>/dev/null | grep -Ei 'time|bucket|encryptions'; done
```

output:

```
s=20
Total number of encryptions: 3191
Bucket size: 3
Total time: 2.622115544s
Total non-preprocessing time: 1.968427236s
s=30
Total number of encryptions: 4377
Bucket size: 4
Total time: 3.502956549s
Total non-preprocessing time: 2.608486608s
s=40
Total number of encryptions: 5627
Bucket size: 5
Total time: 4.527600478s
Total non-preprocessing time: 3.342309507s
s=128
Total number of encryptions: 17575
Bucket size: 15
Total time: 13.80009209s
Total non-preprocessing time: 10.14694803s
```


### Varying the number of outcomes

command:

``` sh
for i in 2 4 8 16 32 64 128 256 512 1024 2048 4096 9192; do echo "n_outcomes=$i"; cargo run --release -- -s 30 --n-outcomes $i --threshold 1 --n-oracles 1 2>/dev/null | grep -Ei 'time|bucket|encryptions'; done
```

output:

```
n_outcomes=2
Total number of encryptions: 64
Bucket size: 16
Total time: 41.708927ms
Total non-preprocessing time: 28.508667ms
n_outcomes=4
Total number of encryptions: 82
Bucket size: 11
Total time: 54.286418ms
Total non-preprocessing time: 37.403311ms
n_outcomes=8
Total number of encryptions: 116
Bucket size: 9
Total time: 79.853111ms
Total non-preprocessing time: 56.011487ms
n_outcomes=16
Total number of encryptions: 177
Bucket size: 8
Total time: 128.138111ms
Total non-preprocessing time: 91.404012ms
n_outcomes=32
Total number of encryptions: 283
Bucket size: 6
Total time: 203.459322ms
Total non-preprocessing time: 144.285653ms
n_outcomes=64
Total number of encryptions: 465
Bucket size: 6
Total time: 355.237011ms
Total non-preprocessing time: 258.467759ms
n_outcomes=128
Total number of encryptions: 775
Bucket size: 5
Total time: 589.363089ms
Total non-preprocessing time: 429.892715ms
n_outcomes=256
Total number of encryptions: 1351
Bucket size: 4
Total time: 1.017361882s
Total non-preprocessing time: 736.990923ms
n_outcomes=512
Total number of encryptions: 2344
Bucket size: 4
Total time: 1.823757723s
Total non-preprocessing time: 1.34322391s
n_outcomes=1024
Total number of encryptions: 4377
Bucket size: 4
Total time: 3.49180033s
Total non-preprocessing time: 2.596716094s
n_outcomes=2048
Total number of encryptions: 7475
Bucket size: 3
Total time: 5.854553468s
Total non-preprocessing time: 4.296269908s
n_outcomes=4096
Total number of encryptions: 13519
Bucket size: 3
Total time: 11.020050745s
Total non-preprocessing time: 8.163228288s
n_outcomes=9192
Total number of encryptions: 28755
Bucket size: 3
Total time: 23.998435729s
Total non-preprocessing time: 17.897570299s
```


### Varying the threshold

command:

``` sh
for i in 1 2 4 8 16 32 64; do threshold=$(expr $i / 2 + 1);  echo "oracles=$i threshold=$threshold"; cargo run --release -- -s 30 --n-outcomes 256 --threshold $threshold --n-oracles $i 2>/dev/null |grep -Ei 'time|bucket|encryptions' ; done
```

output:

```
oracles=1 threshold=1
Total number of encryptions: 1351
Bucket size: 4
Total time: 1.013198999s
Total non-preprocessing time: 733.218864ms
oracles=2 threshold=2
Total number of encryptions: 2407
Bucket size: 4
Total time: 1.896413641s
Total non-preprocessing time: 1.398715793s
oracles=4 threshold=3
Total number of encryptions: 4502
Bucket size: 4
Total time: 3.666766841s
Total non-preprocessing time: 2.739901005s
oracles=8 threshold=5
Total number of encryptions: 8660
Bucket size: 4
Total time: 7.393501254s
Total non-preprocessing time: 5.600673079s
oracles=16 threshold=9
Total number of encryptions: 15795
Bucket size: 3
Total time: 13.150056343s
Total non-preprocessing time: 9.86653418s
oracles=32 threshold=17
Total number of encryptions: 28677
Bucket size: 3
Total time: 26.817488326s
Total non-preprocessing time: 20.919740097s
oracles=64 threshold=33
Total number of encryptions: 54073
Bucket size: 3
Total time: 60.481506459s
Total non-preprocessing time: 49.204428427s
```

