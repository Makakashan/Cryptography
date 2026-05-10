package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"strings"
)

// readElgamalParams reads p and g from the specified file
func readElgamalParams(filename string) (*big.Int, *big.Int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var lines []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}

	if len(lines) < 2 {
		return nil, nil, fmt.Errorf("file must contain at least 2 lines")
	}

	p := new(big.Int)
	if _, ok := p.SetString(lines[0], 10); !ok {
		return nil, nil, fmt.Errorf("invalid p value")
	}

	g := new(big.Int)
	if _, ok := g.SetString(lines[1], 10); !ok {
		return nil, nil, fmt.Errorf("invalid g value")
	}

	return p, g, nil
}

// generateKeys generates an ElGamal key pair
func generateKeys(p, g *big.Int) (*big.Int, *big.Int) {
	// x is random in [2, p-2]
	pMinus2 := new(big.Int).Sub(p, big.NewInt(2))
	x, _ := rand.Int(rand.Reader, new(big.Int).Sub(pMinus2, big.NewInt(1)))
	x.Add(x, big.NewInt(2))

	// y = g^x mod p
	y := new(big.Int).Exp(g, x, p)
	return x, y
}

// writeKey writes a key (p, g, value) to a file
func writeKey(filename string, p, g, value *big.Int) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	fmt.Fprintln(writer, p.String())
	fmt.Fprintln(writer, g.String())
	fmt.Fprintln(writer, value.String())
	return writer.Flush()
}

// readPublicKey reads public key from file
func readPublicKey(filename string) (*big.Int, *big.Int, *big.Int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, nil, nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var lines []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}

	if len(lines) < 3 {
		return nil, nil, nil, fmt.Errorf("public key file must contain 3 lines")
	}

	p := new(big.Int)
	if _, ok := p.SetString(lines[0], 10); !ok {
		return nil, nil, nil, fmt.Errorf("invalid p")
	}

	g := new(big.Int)
	if _, ok := g.SetString(lines[1], 10); !ok {
		return nil, nil, nil, fmt.Errorf("invalid g")
	}

	y := new(big.Int)
	if _, ok := y.SetString(lines[2], 10); !ok {
		return nil, nil, nil, fmt.Errorf("invalid y")
	}

	return p, g, y, nil
}

// readPrivateKey reads private key from file
func readPrivateKey(filename string) (*big.Int, *big.Int, *big.Int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, nil, nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var lines []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}

	if len(lines) < 3 {
		return nil, nil, nil, fmt.Errorf("private key file must contain 3 lines")
	}

	p := new(big.Int)
	if _, ok := p.SetString(lines[0], 10); !ok {
		return nil, nil, nil, fmt.Errorf("invalid p")
	}

	g := new(big.Int)
	if _, ok := g.SetString(lines[1], 10); !ok {
		return nil, nil, nil, fmt.Errorf("invalid g")
	}

	x := new(big.Int)
	if _, ok := x.SetString(lines[2], 10); !ok {
		return nil, nil, nil, fmt.Errorf("invalid x")
	}

	return p, g, x, nil
}

// encrypt performs ElGamal encryption
func encrypt(p, g, y, m *big.Int) (*big.Int, *big.Int) {
	// k is random in [2, p-2]
	pMinus2 := new(big.Int).Sub(p, big.NewInt(2))
	k, _ := rand.Int(rand.Reader, new(big.Int).Sub(pMinus2, big.NewInt(1)))
	k.Add(k, big.NewInt(2))

	// c1 = g^k mod p
	c1 := new(big.Int).Exp(g, k, p)

	// c2 = m * y^k mod p
	yk := new(big.Int).Exp(y, k, p)
	c2 := new(big.Int).Mul(m, yk)
	c2.Mod(c2, p)

	return c1, c2
}

// decrypt performs ElGamal decryption
func decrypt(p, x, c1, c2 *big.Int) *big.Int {
	// s = c1^x mod p
	s := new(big.Int).Exp(c1, x, p)

	// s_inv = s^(-1) mod p
	sInv := new(big.Int).ModInverse(s, p)

	// m = c2 * s_inv mod p
	m := new(big.Int).Mul(c2, sInv)
	m.Mod(m, p)

	return m
}

// sign creates an ElGamal digital signature
func sign(p, g, x, m *big.Int) (*big.Int, *big.Int) {
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))

	for {
		// k is random in [2, p-2] and gcd(k, p-1) = 1
		pMinus2 := new(big.Int).Sub(p, big.NewInt(2))
		k, _ := rand.Int(rand.Reader, new(big.Int).Sub(pMinus2, big.NewInt(1)))
		k.Add(k, big.NewInt(2))

		// Check gcd(k, p-1) == 1
		if new(big.Int).GCD(nil, nil, k, pMinus1).Cmp(big.NewInt(1)) != 0 {
			continue
		}

		// r = g^k mod p
		r := new(big.Int).Exp(g, k, p)

		// k^(-1) mod (p-1)
		kInv := new(big.Int).ModInverse(k, pMinus1)
		if kInv == nil {
			continue
		}

		// s = (m - x*r) * k^(-1) mod (p-1)
		xr := new(big.Int).Mul(x, r)
		xr.Mod(xr, pMinus1)

		mMinusXr := new(big.Int).Sub(m, xr)
		mMinusXr.Mod(mMinusXr, pMinus1)

		s := new(big.Int).Mul(mMinusXr, kInv)
		s.Mod(s, pMinus1)

		// Ensure s is positive
		if s.Sign() <= 0 {
			s.Add(s, pMinus1)
		}

		if s.Sign() > 0 {
			return r, s
		}
	}
}

// verify verifies an ElGamal digital signature
func verify(p, g, y, m, r, s *big.Int) bool {
	// Check 0 < r < p
	if r.Sign() <= 0 || r.Cmp(p) >= 0 {
		return false
	}

	// Check 0 < s < p-1
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	if s.Sign() <= 0 || s.Cmp(pMinus1) >= 0 {
		return false
	}

	// v1 = g^m mod p
	v1 := new(big.Int).Exp(g, m, p)

	// v2 = y^r * r^s mod p
	yr := new(big.Int).Exp(y, r, p)
	rs := new(big.Int).Exp(r, s, p)
	v2 := new(big.Int).Mul(yr, rs)
	v2.Mod(v2, p)

	return v1.Cmp(v2) == 0
}

// readMessage reads a big integer from a file
func readMessage(filename string) (*big.Int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var content string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			content = line
			break
		}
	}

	m := new(big.Int)
	if _, ok := m.SetString(content, 10); !ok {
		return nil, fmt.Errorf("invalid message format")
	}

	return m, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run elgamal.go [-k|-e|-d|-s|-v]")
		os.Exit(1)
	}

	option := os.Args[1]

	switch option {
	case "-k":
		// Generate keys
		p, g, err := readElgamalParams("elgamal.txt")
		if err != nil {
			fmt.Printf("Error reading elgamal.txt: %v\n", err)
			os.Exit(1)
		}

		x, y := generateKeys(p, g)

		if err := writeKey("private.txt", p, g, x); err != nil {
			fmt.Printf("Error writing private key: %v\n", err)
			os.Exit(1)
		}

		if err := writeKey("public.txt", p, g, y); err != nil {
			fmt.Printf("Error writing public key: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Keys generated successfully.")

	case "-e":
		// Encrypt
		p, g, y, err := readPublicKey("public.txt")
		if err != nil {
			fmt.Printf("Error reading public key: %v\n", err)
			os.Exit(1)
		}

		m, err := readMessage("plain.txt")
		if err != nil {
			fmt.Printf("Error reading plain.txt: %v\n", err)
			os.Exit(1)
		}

		if m.Cmp(p) >= 0 {
			fmt.Println("Error: message m must be less than p")
			os.Exit(1)
		}

		c1, c2 := encrypt(p, g, y, m)

		file, err := os.Create("crypto.txt")
		if err != nil {
			fmt.Printf("Error creating crypto.txt: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()

		writer := bufio.NewWriter(file)
		fmt.Fprintln(writer, c1.String())
		fmt.Fprintln(writer, c2.String())
		writer.Flush()

		fmt.Println("Encryption completed.")

	case "-d":
		// Decrypt
		p, _, x, err := readPrivateKey("private.txt")
		if err != nil {
			fmt.Printf("Error reading private key: %v\n", err)
			os.Exit(1)
		}

		file, err := os.Open("crypto.txt")
		if err != nil {
			fmt.Printf("Error reading crypto.txt: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		var lines []string
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				lines = append(lines, line)
			}
		}

		if len(lines) < 2 {
			fmt.Println("Error: crypto.txt must contain 2 lines")
			os.Exit(1)
		}

		c1 := new(big.Int)
		if _, ok := c1.SetString(lines[0], 10); !ok {
			fmt.Println("Error: invalid c1")
			os.Exit(1)
		}

		c2 := new(big.Int)
		if _, ok := c2.SetString(lines[1], 10); !ok {
			fmt.Println("Error: invalid c2")
			os.Exit(1)
		}

		m := decrypt(p, x, c1, c2)

		outFile, err := os.Create("decrypt.txt")
		if err != nil {
			fmt.Printf("Error creating decrypt.txt: %v\n", err)
			os.Exit(1)
		}
		defer outFile.Close()

		fmt.Fprintln(outFile, m.String())
		fmt.Println("Decryption completed.")

	case "-s":
		// Sign
		p, g, x, err := readPrivateKey("private.txt")
		if err != nil {
			fmt.Printf("Error reading private key: %v\n", err)
			os.Exit(1)
		}

		m, err := readMessage("message.txt")
		if err != nil {
			fmt.Printf("Error reading message.txt: %v\n", err)
			os.Exit(1)
		}

		r, s := sign(p, g, x, m)

		file, err := os.Create("signature.txt")
		if err != nil {
			fmt.Printf("Error creating signature.txt: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()

		writer := bufio.NewWriter(file)
		fmt.Fprintln(writer, r.String())
		fmt.Fprintln(writer, s.String())
		writer.Flush()

		fmt.Println("Signature created.")

	case "-v":
		// Verify
		p, g, y, err := readPublicKey("public.txt")
		if err != nil {
			fmt.Printf("Error reading public key: %v\n", err)
			os.Exit(1)
		}

		m, err := readMessage("message.txt")
		if err != nil {
			fmt.Printf("Error reading message.txt: %v\n", err)
			os.Exit(1)
		}

		file, err := os.Open("signature.txt")
		if err != nil {
			fmt.Printf("Error reading signature.txt: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		var lines []string
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				lines = append(lines, line)
			}
		}

		if len(lines) < 2 {
			fmt.Println("Error: signature.txt must contain 2 lines")
			os.Exit(1)
		}

		r := new(big.Int)
		if _, ok := r.SetString(lines[0], 10); !ok {
			fmt.Println("Error: invalid r")
			os.Exit(1)
		}

		s := new(big.Int)
		if _, ok := s.SetString(lines[1], 10); !ok {
			fmt.Println("Error: invalid s")
			os.Exit(1)
		}

		result := verify(p, g, y, m, r, s)
		resultStr := "T"
		if !result {
			resultStr = "N"
		}

		fmt.Println(resultStr)

		outFile, err := os.Create("verify.txt")
		if err != nil {
			fmt.Printf("Error creating verify.txt: %v\n", err)
			os.Exit(1)
		}
		defer outFile.Close()

		fmt.Fprintln(outFile, resultStr)

	default:
		fmt.Println("Invalid option. Use -k, -e, -d, -s, or -v.")
		os.Exit(1)
	}
}
