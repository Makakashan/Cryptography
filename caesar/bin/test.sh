#!/bin/bash

set -euo pipefail

# Test script for Caesar and Affine cipher program

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXAMPLES_DIR="$ROOT_DIR/examples"
OUT_DIR="$ROOT_DIR/out"
BACKUP_DIR="$(mktemp -d)"

cleanup() {
    cp "$BACKUP_DIR"/plain.txt "$EXAMPLES_DIR"/plain.txt
    cp "$BACKUP_DIR"/crypto.txt "$EXAMPLES_DIR"/crypto.txt
    cp "$BACKUP_DIR"/key.txt "$EXAMPLES_DIR"/key.txt
    cp "$BACKUP_DIR"/extra.txt "$EXAMPLES_DIR"/extra.txt
    rm -rf "$BACKUP_DIR"
    rm -f "$OUT_DIR"/*.txt
}
trap cleanup EXIT

cp "$EXAMPLES_DIR"/plain.txt "$BACKUP_DIR"/plain.txt
cp "$EXAMPLES_DIR"/crypto.txt "$BACKUP_DIR"/crypto.txt
cp "$EXAMPLES_DIR"/key.txt "$BACKUP_DIR"/key.txt
cp "$EXAMPLES_DIR"/extra.txt "$BACKUP_DIR"/extra.txt

echo "=== Building program ==="
(
    cd "$ROOT_DIR/src"
    go build -o "$ROOT_DIR/cezar"
)

if [ ! -f "$ROOT_DIR/cezar" ]; then
    echo "Build failed!"
    exit 1
fi

echo "✓ Build successful"
echo ""

# Create out directory if it doesn't exist
mkdir -p "$OUT_DIR"

# Test 1: Caesar cipher encryption
echo "=== Test 1: Caesar Cipher Encryption ==="
echo "HELLO WORLD" > "$EXAMPLES_DIR/plain.txt"
echo "3" > "$EXAMPLES_DIR/key.txt"
"$ROOT_DIR/cezar" -c -e

if [ -f "$OUT_DIR/crypto.txt" ]; then
    actual="$(cat "$OUT_DIR/crypto.txt")"
    echo "✓ Encryption successful"
    echo "Plaintext: $(cat "$EXAMPLES_DIR/plain.txt")"
    echo "Ciphertext: $actual"
    [ "$actual" = "KHOOR ZRUOG" ] || { echo "✗ Unexpected Caesar encryption output"; exit 1; }
else
    echo "✗ Encryption failed"
fi
echo ""

# Test 2: Caesar cipher decryption
echo "=== Test 2: Caesar Cipher Decryption ==="
echo "KHOOR ZRUOG" > "$EXAMPLES_DIR/crypto.txt"
echo "3" > "$EXAMPLES_DIR/key.txt"
"$ROOT_DIR/cezar" -c -d

if [ -f "$OUT_DIR/decrypt.txt" ]; then
    actual="$(cat "$OUT_DIR/decrypt.txt")"
    echo "✓ Decryption successful"
    echo "Decrypted: $actual"
    [ "$actual" = "HELLO WORLD" ] || { echo "✗ Unexpected Caesar decryption output"; exit 1; }
else
    echo "✗ Decryption failed"
fi
echo ""

# Test 3: Affine cipher encryption
echo "=== Test 3: Affine Cipher Encryption ==="
echo "THE QUICK BROWN FOX" > "$EXAMPLES_DIR/plain.txt"
echo "3 5" > "$EXAMPLES_DIR/key.txt"
"$ROOT_DIR/cezar" -a -e

if [ -f "$OUT_DIR/crypto.txt" ]; then
    actual="$(cat "$OUT_DIR/crypto.txt")"
    echo "✓ Encryption successful"
    echo "Plaintext: $(cat "$EXAMPLES_DIR/plain.txt")"
    echo "Ciphertext: $actual"
    [ "$actual" = "UMX FZRNB IKVJQ CVO" ] || { echo "✗ Unexpected affine encryption output"; exit 1; }
else
    echo "✗ Encryption failed"
fi
echo ""

# Test 4: Affine cipher decryption
echo "=== Test 4: Affine Cipher Decryption ==="
echo "UMX FZRNB IKVJQ CVO" > "$EXAMPLES_DIR/crypto.txt"
echo "3 5" > "$EXAMPLES_DIR/key.txt"
"$ROOT_DIR/cezar" -a -d

if [ -f "$OUT_DIR/decrypt.txt" ]; then
    actual="$(cat "$OUT_DIR/decrypt.txt")"
    echo "✓ Decryption successful"
    echo "Decrypted: $actual"
    [ "$actual" = "THE QUICK BROWN FOX" ] || { echo "✗ Unexpected affine decryption output"; exit 1; }
else
    echo "✗ Decryption failed"
fi
echo ""

# Test 5: Known plaintext attack - Caesar
echo "=== Test 5: Known Plaintext Attack (Caesar) ==="
echo "OLSSV DVYSK" > "$EXAMPLES_DIR/crypto.txt"
echo "HELLO" > "$EXAMPLES_DIR/extra.txt"
"$ROOT_DIR/cezar" -c -j

if [ -f "$OUT_DIR/key-found.txt" ]; then
    found_key="$(cat "$OUT_DIR/key-found.txt")"
    actual="$(cat "$OUT_DIR/decrypt.txt")"
    echo "✓ Cryptanalysis successful"
    echo "Found key: $found_key"
    echo "Decrypted: $actual"
    [ "$found_key" = "7" ] || { echo "✗ Unexpected Caesar known-plaintext key"; exit 1; }
    [ "$actual" = "HELLO WORLD" ] || { echo "✗ Unexpected Caesar known-plaintext decrypt"; exit 1; }
else
    echo "✗ Cryptanalysis failed"
fi
echo ""

# Test 6: Known plaintext attack - Affine
echo "=== Test 6: Known Plaintext Attack (Affine) ==="
echo "ZRC KEWSG NPAOV HAT" > "$EXAMPLES_DIR/crypto.txt"
echo "THE QUICK" > "$EXAMPLES_DIR/extra.txt"
"$ROOT_DIR/cezar" -a -j

if [ -f "$OUT_DIR/key-found.txt" ]; then
    found_key="$(cat "$OUT_DIR/key-found.txt")"
    actual="$(cat "$OUT_DIR/decrypt.txt")"
    echo "✓ Cryptanalysis successful"
    echo "Found key: $found_key"
    echo "Decrypted: $actual"
    [ "$found_key" = "8 5" ] || { echo "✗ Unexpected affine known-plaintext key"; exit 1; }
    [ "$actual" = "THE QUICK BROWN FOX" ] || { echo "✗ Unexpected affine known-plaintext decrypt"; exit 1; }
else
    echo "✗ Cryptanalysis failed"
fi
echo ""

# Test 7: Brute force - Caesar
echo "=== Test 7: Brute Force Attack (Caesar) ==="
echo "FRPERG ZRFFNTR" > "$EXAMPLES_DIR/crypto.txt"
"$ROOT_DIR/cezar" -c -k

if [ -f "$OUT_DIR/decrypt.txt" ]; then
    echo "✓ Brute force successful"
    echo "First 3 results:"
    head -n 3 "$OUT_DIR/decrypt.txt"
    [ "$(wc -l < "$OUT_DIR/decrypt.txt")" -eq 25 ] || { echo "✗ Caesar brute-force should have 25 variants"; exit 1; }
else
    echo "✗ Brute force failed"
fi
echo ""

# Test 8: Brute force - Affine (limited output)
echo "=== Test 8: Brute Force Attack (Affine) ==="
echo "YBPY" > "$EXAMPLES_DIR/crypto.txt"
"$ROOT_DIR/cezar" -a -k

if [ -f "$OUT_DIR/decrypt.txt" ]; then
    total="$(wc -l < "$OUT_DIR/decrypt.txt")"
    echo "✓ Brute force successful"
    echo "First 5 results:"
    head -n 5 "$OUT_DIR/decrypt.txt"
    echo "Total variants: $total"
    [ "$total" -eq 311 ] || { echo "✗ Affine brute-force should have 311 variants"; exit 1; }
else
    echo "✗ Brute force failed"
fi
echo ""

echo ""
echo "=== All tests completed ==="
