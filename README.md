# Caesar and Affine Cipher

## What it can do
- Caesar cipher (`-c`)
- Affine cipher (`-a`)
- Encrypt (`-e`)
- Decrypt (`-d`)
- Known-plaintext attack (`-j`)
- Brute-force attack (`-k`)

## Folders
- `src/` source code
- `bin/` compiled binary
- `examples/` input files
- `out/` output files
- `test.sh` tests

## Build
```bash
cd src
go build -o ../bin/cezar
cd ..
```

## Run
```bash
./bin/cezar [-c|-a] [-e|-d|-j|-k]
```

Use exactly:
- one cipher option: `-c` or `-a`
- one mode option: `-e`, `-d`, `-j`, or `-k`

## Input and output files
Input (read from `examples/`):
- `plain.txt` for encryption
- `crypto.txt` for decryption and attacks
- `key.txt` for encryption/decryption
- `extra.txt` for known-plaintext attack

Output (written to `out/`):
- `crypto.txt` encrypted text
- `decrypt.txt` decrypted text or brute-force variants
- `key-found.txt` found key for `-j`

Program reads only required files for chosen mode.
Program creates output files if needed.

## Key format (`examples/key.txt`)
Caesar:
```text
3
```

Affine:
```text
3 5
```
Meaning:
- first number is `b` (shift)
- second number is `a` (multiplier)

For affine cipher, `a` must be coprime with 26.
Valid `a`: `1,3,5,7,9,11,15,17,19,21,23,25`

## Quick examples
Encrypt (affine):
```bash
./bin/cezar -a -e
```

Decrypt (affine):
```bash
./bin/cezar -a -d
```

Known-plaintext attack (Caesar):
```bash
./bin/cezar -c -j
```

Brute-force attack (Caesar):
```bash
./bin/cezar -c -k
```

## Tests
```bash
./test.sh
```
