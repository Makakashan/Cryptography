# xor (Go)

A small CLI tool that demonstrates why reusing a one-time pad key is insecure.

## Modes

- `-p` — prepare text: `orig.txt -> plain.txt`
- `-e` — encrypt: `plain.txt + key.txt -> crypto.txt`
- `-k` — ciphertext-only cryptanalysis: `crypto.txt -> decrypt.txt`

## File Roles

- `orig.txt`  
  Source text (any readable text, around 1 KB).  
  Used only in prepare mode.

- `plain.txt`  
  Prepared plaintext for the assignment:
  - only English letters (`A-Z`, `a-z`) and spaces
  - split into lines of exactly 64 characters

- `key.txt`  
  Key of exactly 64 bytes.  
  The same key is reused for every plaintext line (intentionally, for demonstration).

- `crypto.txt`  
  Ciphertext output.  
  Each line is `plain_line XOR key`, stored as hex text (safe to parse and view).

- `decrypt.txt`  
  Cryptanalysis result recovered from ciphertext only.  
  Unknown characters are written as `_`.

## Build and Run

```/dev/null/cmd.sh#L1-5
cd "/home/makakashan/Documents/My Favourite Ug/Crypto2026/xor"
go build -o xor .
./xor -p
./xor -e
./xor -k
```
