package main

import (
	"encoding/hex"
	"fmt"
	"math/bits"
	"os"
)

func bitDiff(hexA, hexB string) (int, int, error) {
	left, err := hex.DecodeString(hexA)
	if err != nil {
		return 0, 0, err
	}

	right, err := hex.DecodeString(hexB)
	if err != nil {
		return 0, 0, err
	}

	if len(left) != len(right) {
		return 0, 0, fmt.Errorf("hashes must have the same length")
	}

	diff := 0
	for i := range left {
		diff += bits.OnesCount8(left[i] ^ right[i])
	}

	return diff, len(left) * 8, nil
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s HASH1 HASH2\n", os.Args[0])
		os.Exit(1)
	}

	diff, total, err := bitDiff(os.Args[1], os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	percent := int(float64(diff)*100/float64(total) + 0.5)
	fmt.Printf("Liczba rozniacych sie bitow: %d z %d, procentowo: %d%%.\n", diff, total, percent)
}
