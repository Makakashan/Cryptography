package main

import "strings"

func caesarEncrypt(text string, shift int) string {
	var result strings.Builder
	shift = ((shift % ALPHABET_SIZE) + ALPHABET_SIZE) % ALPHABET_SIZE

	for _, c := range text {
		if c == ' ' {
			result.WriteRune(' ')
		} else {
			num := charToNum(c)
			if num != -1 {
				encrypted := (num + shift) % ALPHABET_SIZE
				result.WriteRune(numToChar(encrypted))
			}
		}
	}

	return result.String()
}

func caesarDecrypt(text string, shift int) string {
	return caesarEncrypt(text, -shift)
}
