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
Total elapsed: 1.274426324s sans-preprocessing: 935.448041ms transmitted: 913871 non-interactive: 904816
Params s: 30 n_oracles: 1 threshold: 1 n_encryptions: 4377 bucket_size: 4 proportion_closed: 0.936
Total elapsed: 1.722022463s sans-preprocessing: 1.25441172s transmitted: 1238261 non-interactive: 1225650
Params s: 40 n_oracles: 1 threshold: 1 n_encryptions: 5627 bucket_size: 5 proportion_closed: 0.91
Total elapsed: 2.172743771s sans-preprocessing: 1.574999694s transmitted: 1573063 non-interactive: 1556722
Params s: 128 n_oracles: 1 threshold: 1 n_encryptions: 17575 bucket_size: 15 proportion_closed: 0.874
Total elapsed: 6.559367074s sans-preprocessing: 4.678337613s transmitted: 4831289 non-interactive: 4779122
```


### Varying the number of outcomes

command:

``` sh
for i in 2 4 8 16 32 64 128 256 512 1024 2048 4096 9192; do  cargo run --release -- -s 30 --n-outcomes $i --threshold 1 --n-oracles 1 2>/dev/null | grep -Ei 'Params|Total'; done
```

output:

```
Params s: 30 n_oracles: 1 threshold: 1 n_encryptions: 64 bucket_size: 16 proportion_closed: 0.5
Total elapsed: 19.942078ms sans-preprocessing: 13.010771ms transmitted: 14410 non-interactive: 14344
Params s: 30 n_oracles: 1 threshold: 1 n_encryptions: 82 bucket_size: 11 proportion_closed: 0.537
Total elapsed: 26.107656ms sans-preprocessing: 17.301135ms transmitted: 18846 non-interactive: 18762
Params s: 30 n_oracles: 1 threshold: 1 n_encryptions: 116 bucket_size: 9 proportion_closed: 0.621
Total elapsed: 38.470937ms sans-preprocessing: 26.151376ms transmitted: 27908 non-interactive: 27790
Params s: 30 n_oracles: 1 threshold: 1 n_encryptions: 177 bucket_size: 8 proportion_closed: 0.724
Total elapsed: 62.508245ms sans-preprocessing: 43.660216ms transmitted: 44907 non-interactive: 44728
Params s: 30 n_oracles: 1 threshold: 1 n_encryptions: 283 bucket_size: 6 proportion_closed: 0.679
Total elapsed: 99.041041ms sans-preprocessing: 68.555512ms transmitted: 70205 non-interactive: 69898
Params s: 30 n_oracles: 1 threshold: 1 n_encryptions: 465 bucket_size: 6 proportion_closed: 0.826
Total elapsed: 171.397127ms sans-preprocessing: 121.774709ms transmitted: 124441 non-interactive: 123630
Params s: 30 n_oracles: 1 threshold: 1 n_encryptions: 775 bucket_size: 5 proportion_closed: 0.826
Total elapsed: 294.946899ms sans-preprocessing: 204.959963ms transmitted: 207797 non-interactive: 206062
Params s: 30 n_oracles: 1 threshold: 1 n_encryptions: 1351 bucket_size: 4 proportion_closed: 0.758
Total elapsed: 481.866748ms sans-preprocessing: 336.571969ms transmitted: 350925 non-interactive: 347506
Params s: 30 n_oracles: 1 threshold: 1 n_encryptions: 2344 bucket_size: 4 proportion_closed: 0.874
Total elapsed: 890.359214ms sans-preprocessing: 638.766767ms transmitted: 644186 non-interactive: 637714
Params s: 30 n_oracles: 1 threshold: 1 n_encryptions: 4377 bucket_size: 4 proportion_closed: 0.936
Total elapsed: 1.743307342s sans-preprocessing: 1.270044292s transmitted: 1238241 non-interactive: 1225650
Params s: 30 n_oracles: 1 threshold: 1 n_encryptions: 7475 bucket_size: 3 proportion_closed: 0.822
Total elapsed: 2.756100704s sans-preprocessing: 1.959705885s transmitted: 2006345 non-interactive: 1984498
Params s: 30 n_oracles: 1 threshold: 1 n_encryptions: 13519 bucket_size: 3 proportion_closed: 0.909
Total elapsed: 5.250113538s sans-preprocessing: 3.811438293s transmitted: 3780037 non-interactive: 3740018
Params s: 30 n_oracles: 1 threshold: 1 n_encryptions: 28755 bucket_size: 3 proportion_closed: 0.959
Total elapsed: 11.540996428s sans-preprocessing: 8.46935377s transmitted: 8225497 non-interactive: 8139738

```


### Varying the threshold

command:

``` sh
for i in 1 2 4 8 16 32 64; do threshold=$(expr $i / 2 + 1);  cargo run --release -- -s 30 --n-outcomes 256 --threshold $threshold --n-oracles $i 2>/dev/null |grep -Ei 'Params|Total' ; done
```

output:

```
Params s: 30 n_oracles: 1 threshold: 1 n_encryptions: 1351 bucket_size: 4 proportion_closed: 0.758
Total elapsed: 477.94411ms sans-preprocessing: 334.428543ms transmitted: 350945 non-interactive: 347506
Params s: 30 n_oracles: 2 threshold: 2 n_encryptions: 2407 bucket_size: 4 proportion_closed: 0.851
Total elapsed: 903.379194ms sans-preprocessing: 645.682642ms transmitted: 662383 non-interactive: 655730
Params s: 30 n_oracles: 4 threshold: 3 n_encryptions: 4502 bucket_size: 4 proportion_closed: 0.91
Total elapsed: 1.772694581s sans-preprocessing: 1.290346259s transmitted: 1274224 non-interactive: 1261266
Params s: 30 n_oracles: 8 threshold: 5 n_encryptions: 8660 bucket_size: 4 proportion_closed: 0.946
Total elapsed: 3.50377894s sans-preprocessing: 2.572126717s transmitted: 2492662 non-interactive: 2467218
Params s: 30 n_oracles: 16 threshold: 9 n_encryptions: 15795 bucket_size: 3 proportion_closed: 0.778
Total elapsed: 5.825807163s sans-preprocessing: 4.140301434s transmitted: 4212663 non-interactive: 4165874
Params s: 30 n_oracles: 32 threshold: 17 n_encryptions: 28677 bucket_size: 3 proportion_closed: 0.857
Total elapsed: 11.349690911s sans-preprocessing: 8.280530103s transmitted: 7950859 non-interactive: 7865394
Params s: 30 n_oracles: 64 threshold: 33 n_encryptions: 54073 bucket_size: 3 proportion_closed: 0.909
Total elapsed: 23.487008157s sans-preprocessing: 17.71730371s transmitted: 15367223 non-interactive: 15205556
```
