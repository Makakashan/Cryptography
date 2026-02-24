package main

import "fmt"

const ALPHABET_SIZE = 26

func gcd(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

func modInverse(a, m int) (int, error) {
	if gcd(a, m) != 1 {
		return 0, fmt.Errorf("no modular inverse for %d mod %d", a, m)
	}

	m0, x0, x1 := m, 0, 1

	for a > 1 {
		q := a / m
		m, a = a%m, m
		x0, x1 = x1-q*x0, x0
	}

	if x1 < 0 {
		x1 += m0
	}

	return x1, nil
}

func charToNum(c rune) int {
	if c >= 'A' && c <= 'Z' {
		return int(c - 'A')
	}
	if c >= 'a' && c <= 'z' {
		return int(c - 'a')
	}
	return -1
}

func numToChar(n int) rune {
	return rune('A' + n)
}
