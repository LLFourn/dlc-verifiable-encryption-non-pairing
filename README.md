# Sketch of DLCs using cut-and-choose verifiable encryption (prime-order group edition)

important points:

1. I implemented the cut-and-choose interactively (not via Fiat-Shamir) but this could easily be changed.
2. I don't actually use adaptor signature per se. Rather we are just one-time padding scalars which are passed in. In reality these could indeed be Schnorr signatures on a particular message and R values.

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
for i in 20 30 40 128; do cargo run --release -- -s $i --n-outcomes 1024 --threshold 1 --n-oracles 1 2>/dev/null | grep -Ei 'Total|Params'; done
```

output:

```
Params s: 20 n_oracles: 1 threshold: 1 n_encryptions: 3191 bucket_size: 3 proportion_closed: 0.963
Total elapsed: 2.614121288s sans-preprocessing: 1.953474144s transmitted: 828210 non-interactive: 819151
Params s: 30 n_oracles: 1 threshold: 1 n_encryptions: 4377 bucket_size: 4 proportion_closed: 0.936
Total elapsed: 3.486989395s sans-preprocessing: 2.594099431s transmitted: 1124404 non-interactive: 1111799
Params s: 40 n_oracles: 1 threshold: 1 n_encryptions: 5627 bucket_size: 5 proportion_closed: 0.91
Total elapsed: 4.440226468s sans-preprocessing: 3.283423892s transmitted: 1431214 non-interactive: 1414877
Params s: 128 n_oracles: 1 threshold: 1 n_encryptions: 17575 bucket_size: 15 proportion_closed: 0.874
Total elapsed: 13.640727812s sans-preprocessing: 10.007579733s transmitted: 4407832 non-interactive: 4355681
```


### Varying the number of outcomes

command:

``` sh
for i in 2 4 8 16 32 64 128 256 512 1024 2048 4096 9192; do  cargo run --release -- -s 30 --n-outcomes $i --threshold 1 --n-oracles 1 2>/dev/null | grep -Ei 'Params|Total'; done
```

output:

```
Params s: 30 n_oracles: 1 threshold: 1 n_encryptions: 64 bucket_size: 16 proportion_closed: 0.5
Total elapsed: 42.442111ms sans-preprocessing: 28.866091ms transmitted: 13608 non-interactive: 13542
Params s: 30 n_oracles: 1 threshold: 1 n_encryptions: 82 bucket_size: 11 proportion_closed: 0.537
Total elapsed: 54.658174ms sans-preprocessing: 37.598525ms transmitted: 17726 non-interactive: 17642
Params s: 30 n_oracles: 1 threshold: 1 n_encryptions: 116 bucket_size: 9 proportion_closed: 0.621
Total elapsed: 80.675287ms sans-preprocessing: 56.398627ms transmitted: 26022 non-interactive: 25904
Params s: 30 n_oracles: 1 threshold: 1 n_encryptions: 177 bucket_size: 8 proportion_closed: 0.724
Total elapsed: 129.742641ms sans-preprocessing: 92.835966ms transmitted: 41466 non-interactive: 41287
Params s: 30 n_oracles: 1 threshold: 1 n_encryptions: 283 bucket_size: 6 proportion_closed: 0.679
Total elapsed: 200.95488ms sans-preprocessing: 142.228293ms transmitted: 65096 non-interactive: 64791
Params s: 30 n_oracles: 1 threshold: 1 n_encryptions: 465 bucket_size: 6 proportion_closed: 0.826
Total elapsed: 354.305027ms sans-preprocessing: 258.262075ms transmitted: 113928 non-interactive: 113115
Params s: 30 n_oracles: 1 threshold: 1 n_encryptions: 775 bucket_size: 5 proportion_closed: 0.826
Total elapsed: 592.803745ms sans-preprocessing: 432.095645ms transmitted: 190278 non-interactive: 188541
Params s: 30 n_oracles: 1 threshold: 1 n_encryptions: 1351 bucket_size: 4 proportion_closed: 0.758
Total elapsed: 1.004648465s sans-preprocessing: 721.752632ms transmitted: 323256 non-interactive: 319809
Params s: 30 n_oracles: 1 threshold: 1 n_encryptions: 2344 bucket_size: 4 proportion_closed: 0.874
Total elapsed: 1.827260875s sans-preprocessing: 1.342952004s transmitted: 587730 non-interactive: 581252
Params s: 30 n_oracles: 1 threshold: 1 n_encryptions: 4377 bucket_size: 4 proportion_closed: 0.936
Total elapsed: 3.541953959s sans-preprocessing: 2.639763267s transmitted: 1124404 non-interactive: 1111799
Params s: 30 n_oracles: 1 threshold: 1 n_encryptions: 7475 bucket_size: 3 proportion_closed: 0.822
Total elapsed: 5.746483019s sans-preprocessing: 4.200566408s transmitted: 1838284 non-interactive: 1816453
Params s: 30 n_oracles: 1 threshold: 1 n_encryptions: 13519 bucket_size: 3 proportion_closed: 0.909
Total elapsed: 10.776052907s sans-preprocessing: 7.980564905s transmitted: 3439672 non-interactive: 3399641
Params s: 30 n_oracles: 1 threshold: 1 n_encryptions: 28755 bucket_size: 3 proportion_closed: 0.959
Total elapsed: 23.532350455s sans-preprocessing: 17.575336333s transmitted: 7456888 non-interactive: 7371141
```


### Varying the threshold

command:

``` sh
for i in 1 2 4 8 16 32 64; do threshold=$(expr $i / 2 + 1);  cargo run --release -- -s 30 --n-outcomes 256 --threshold $threshold --n-oracles $i 2>/dev/null |grep -Ei 'Params|Total' ; done
```

output:

```
Params s: 30 n_oracles: 1 threshold: 1 n_encryptions: 1351 bucket_size: 4 proportion_closed: 0.758
Total elapsed: 991.841275ms sans-preprocessing: 716.017304ms transmitted: 323256 non-interactive: 319809
Params s: 30 n_oracles: 2 threshold: 2 n_encryptions: 2407 bucket_size: 4 proportion_closed: 0.851
Total elapsed: 1.876650788s sans-preprocessing: 1.383366915s transmitted: 606370 non-interactive: 599713
Params s: 30 n_oracles: 4 threshold: 3 n_encryptions: 4502 bucket_size: 4 proportion_closed: 0.91
Total elapsed: 3.653410396s sans-preprocessing: 2.725746388s transmitted: 1161266 non-interactive: 1148302
Params s: 30 n_oracles: 8 threshold: 5 n_encryptions: 8660 bucket_size: 4 proportion_closed: 0.946
Total elapsed: 7.247581237s sans-preprocessing: 5.475564776s transmitted: 2265716 non-interactive: 2240264
Params s: 30 n_oracles: 16 threshold: 9 n_encryptions: 15795 bucket_size: 3 proportion_closed: 0.778
Total elapsed: 12.938041387s sans-preprocessing: 9.704632021s transmitted: 3881160 non-interactive: 3834373
Params s: 30 n_oracles: 32 threshold: 17 n_encryptions: 28677 bucket_size: 3 proportion_closed: 0.857
Total elapsed: 26.548534928s sans-preprocessing: 20.67049082s transmitted: 7279116 non-interactive: 7193659
Params s: 30 n_oracles: 64 threshold: 33 n_encryptions: 54073 bucket_size: 3 proportion_closed: 0.909
Total elapsed: 59.740762625s sans-preprocessing: 48.608402915s transmitted: 14013926 non-interactive: 13852247
```
