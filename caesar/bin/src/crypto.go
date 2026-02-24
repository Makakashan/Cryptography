package main

import "fmt"

func caesarCryptanalysisKnownPlaintext(crypto, plain string) (int, error) {
	if len(crypto) == 0 || len(plain) == 0 {
		return 0, fmt.Errorf("empty text")
	}

	var cryptoChar, plainChar rune
	for _, c := range crypto {
		if c != ' ' {
			cryptoChar = c
			break
		}
	}
	for _, c := range plain {
		if c != ' ' {
			plainChar = c
			break
		}
	}

	if cryptoChar == 0 || plainChar == 0 {
		return 0, fmt.Errorf("no letters found")
	}

	cryptoNum := charToNum(cryptoChar)
	plainNum := charToNum(plainChar)

	shift := (cryptoNum - plainNum + ALPHABET_SIZE) % ALPHABET_SIZE
	return shift, nil
}

func affineCryptanalysisKnownPlaintext(crypto, plain string) (int, int, error) {
	var pairs [][2]int

	pRunes := []rune(plain)
	cRunes := []rune(crypto)

	pIdx, cIdx := 0, 0

	for pIdx < len(pRunes) && cIdx < len(cRunes) {
		if pRunes[pIdx] == ' ' {
			pIdx++
			continue
		}
		if cRunes[cIdx] == ' ' {
			cIdx++
			continue
		}

		p := charToNum(pRunes[pIdx])
		c := charToNum(cRunes[cIdx])

		if p != -1 && c != -1 {
			pairs = append(pairs, [2]int{p, c})
		}

		pIdx++
		cIdx++
	}

	if len(pairs) < 2 {
		return 0, 0, fmt.Errorf("insufficient data")
	}

	var p1, p2, c1, c2 int
	found := false

	for i := 0; i < len(pairs) && !found; i++ {
		p1, c1 = pairs[i][0], pairs[i][1]
		for j := i + 1; j < len(pairs); j++ {
			p2, c2 = pairs[j][0], pairs[j][1]
			if p1 != p2 {
				diffP := (p1 - p2 + ALPHABET_SIZE) % ALPHABET_SIZE
				if diffP != 0 && gcd(diffP, ALPHABET_SIZE) == 1 {
					found = true
					break
				}
			}
		}
	}

	if !found {
		return 0, 0, fmt.Errorf("cannot find suitable letter pairs")
	}

	diffC := (c1 - c2 + ALPHABET_SIZE) % ALPHABET_SIZE
	diffP := (p1 - p2 + ALPHABET_SIZE) % ALPHABET_SIZE

	diffPInv, err := modInverse(diffP, ALPHABET_SIZE)
	if err != nil {
		return 0, 0, err
	}

	a := (diffC * diffPInv) % ALPHABET_SIZE

	if gcd(a, ALPHABET_SIZE) != 1 {
		return 0, 0, fmt.Errorf("found key a=%d is not coprime with 26", a)
	}

	b := (c1 - a*p1 + ALPHABET_SIZE*ALPHABET_SIZE) % ALPHABET_SIZE

	return a, b, nil
}
