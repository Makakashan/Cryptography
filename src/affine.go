package main

import "strings"

func affineEncrypt(text string, a, b int) string {
	var result strings.Builder

	for _, c := range text {
		if c == ' ' {
			result.WriteRune(' ')
		} else {
			num := charToNum(c)
			if num != -1 {
				encrypted := (a*num + b) % ALPHABET_SIZE
				result.WriteRune(numToChar(encrypted))
			}
		}
	}

	return result.String()
}

func affineDecrypt(text string, a, b int) (string, error) {
	aInv, err := modInverse(a, ALPHABET_SIZE)
	if err != nil {
		return "", err
	}

	var result strings.Builder

	for _, c := range text {
		if c == ' ' {
			result.WriteRune(' ')
		} else {
			num := charToNum(c)
			if num != -1 {
				decrypted := (aInv * (num - b + ALPHABET_SIZE*10)) % ALPHABET_SIZE
				result.WriteRune(numToChar(decrypted))
			}
		}
	}

	return result.String(), nil
}

func getAllAffineKeys() [][2]int {
	var keys [][2]int
	validA := []int{1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25}

	for _, a := range validA {
		for b := 0; b < ALPHABET_SIZE; b++ {
			if a == 1 && b == 0 {
				continue
			}
			keys = append(keys, [2]int{a, b})
		}
	}

	return keys
}
