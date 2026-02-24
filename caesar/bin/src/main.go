package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	inputDir  string
	outputDir string
)

func main() {
	if err := resolvePaths(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	os.MkdirAll(outputDir, 0755)

	var useCaesar, useAffine bool
	var opType string

	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch arg {
		case "-c":
			useCaesar = true
		case "-a":
			useAffine = true
		case "-e":
			opType = "encrypt"
		case "-d":
			opType = "decrypt"
		case "-j":
			opType = "known-plaintext"
		case "-k":
			opType = "brute-force"
		}
	}

	if (!useCaesar && !useAffine) || opType == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s [-c|-a] [-e|-d|-j|-k]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  -c: Caesar cipher\n")
		fmt.Fprintf(os.Stderr, "  -a: Affine cipher\n")
		fmt.Fprintf(os.Stderr, "  -e: encryption\n")
		fmt.Fprintf(os.Stderr, "  -d: decryption\n")
		fmt.Fprintf(os.Stderr, "  -j: cryptanalysis with known plaintext\n")
		fmt.Fprintf(os.Stderr, "  -k: brute-force cryptanalysis\n")
		os.Exit(1)
	}

	if useCaesar && useAffine {
		fmt.Fprintf(os.Stderr, "Error: choose only one cipher type\n")
		os.Exit(1)
	}

	var err error

	switch opType {
	case "encrypt":
		err = doEncrypt(useCaesar)
	case "decrypt":
		err = doDecrypt(useCaesar)
	case "known-plaintext":
		err = doKnownPlaintextAttack(useCaesar)
	case "brute-force":
		err = doBruteForce(useCaesar)
	default:
		fmt.Fprintf(os.Stderr, "Unknown operation: %s\n", opType)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func resolvePaths() error {
	if dirExists("examples") {
		inputDir = "examples"
		outputDir = "out"
		return nil
	}

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot detect executable path: %v", err)
	}

	baseDir := filepath.Dir(execPath)
	execInput := filepath.Join(baseDir, "examples")
	if dirExists(execInput) {
		inputDir = execInput
		outputDir = filepath.Join(baseDir, "out")
		return nil
	}

	return fmt.Errorf("cannot find input directory 'examples' near current directory or executable")
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func doEncrypt(useCaesar bool) error {
	plaintext, err := readFile(inputDir + "/plain.txt")
	if err != nil {
		return fmt.Errorf("reading %s/plain.txt: %v", inputDir, err)
	}

	shift, a, err := readKey(inputDir + "/key.txt")
	if err != nil {
		return fmt.Errorf("reading %s/key.txt: %v", inputDir, err)
	}

	var ciphertext string

	if useCaesar {
		ciphertext = caesarEncrypt(plaintext, shift)
	} else {
		if gcd(a, ALPHABET_SIZE) != 1 {
			return fmt.Errorf("key a=%d is not coprime with 26", a)
		}
		ciphertext = affineEncrypt(plaintext, a, shift)
	}

	err = writeFile(outputDir+"/crypto.txt", ciphertext)
	if err != nil {
		return fmt.Errorf("writing %s/crypto.txt: %v", outputDir, err)
	}

	fmt.Println("Encryption completed successfully")
	return nil
}

func doDecrypt(useCaesar bool) error {
	ciphertext, err := readFile(inputDir + "/crypto.txt")
	if err != nil {
		return fmt.Errorf("reading %s/crypto.txt: %v", inputDir, err)
	}

	shift, a, err := readKey(inputDir + "/key.txt")
	if err != nil {
		return fmt.Errorf("reading %s/key.txt: %v", inputDir, err)
	}

	var plaintext string

	if useCaesar {
		plaintext = caesarDecrypt(ciphertext, shift)
	} else {
		if gcd(a, ALPHABET_SIZE) != 1 {
			return fmt.Errorf("key a=%d is not coprime with 26", a)
		}
		plaintext, err = affineDecrypt(ciphertext, a, shift)
		if err != nil {
			return fmt.Errorf("decryption: %v", err)
		}
	}

	err = writeFile(outputDir+"/decrypt.txt", plaintext)
	if err != nil {
		return fmt.Errorf("writing %s/decrypt.txt: %v", outputDir, err)
	}

	fmt.Println("Decryption completed successfully")
	return nil
}

func doKnownPlaintextAttack(useCaesar bool) error {
	ciphertext, err := readFile(inputDir + "/crypto.txt")
	if err != nil {
		return fmt.Errorf("reading %s/crypto.txt: %v", inputDir, err)
	}

	extratext, err := readFile(inputDir + "/extra.txt")
	if err != nil {
		return fmt.Errorf("reading %s/extra.txt: %v", inputDir, err)
	}

	var keyStr string
	var plaintext string

	if useCaesar {
		shift, err := caesarCryptanalysisKnownPlaintext(ciphertext, extratext)
		if err != nil {
			return fmt.Errorf("cryptanalysis: %v", err)
		}

		keyStr = fmt.Sprintf("%d", shift)
		plaintext = caesarDecrypt(ciphertext, shift)
	} else {
		a, b, err := affineCryptanalysisKnownPlaintext(ciphertext, extratext)
		if err != nil {
			return fmt.Errorf("cryptanalysis: %v", err)
		}

		keyStr = fmt.Sprintf("%d %d", b, a)
		plaintext, err = affineDecrypt(ciphertext, a, b)
		if err != nil {
			return fmt.Errorf("decryption: %v", err)
		}
	}

	err = writeFile(outputDir+"/key-found.txt", keyStr)
	if err != nil {
		return fmt.Errorf("writing %s/key-found.txt: %v", outputDir, err)
	}

	err = writeFile(outputDir+"/decrypt.txt", plaintext)
	if err != nil {
		return fmt.Errorf("writing %s/decrypt.txt: %v", outputDir, err)
	}

	fmt.Println("Cryptanalysis completed successfully")
	fmt.Printf("Found key: %s\n", keyStr)
	return nil
}

func doBruteForce(useCaesar bool) error {
	ciphertext, err := readFile(inputDir + "/crypto.txt")
	if err != nil {
		return fmt.Errorf("reading %s/crypto.txt: %v", inputDir, err)
	}

	var results strings.Builder

	if useCaesar {
		for shift := 1; shift < ALPHABET_SIZE; shift++ {
			plaintext := caesarDecrypt(ciphertext, shift)
			results.WriteString(fmt.Sprintf("Key %d: %s\n", shift, plaintext))
		}
	} else {
		keys := getAllAffineKeys()
		for _, key := range keys {
			a, b := key[0], key[1]
			plaintext, err := affineDecrypt(ciphertext, a, b)
			if err != nil {
				continue
			}
			results.WriteString(fmt.Sprintf("Key a=%d b=%d: %s\n", a, b, plaintext))
		}
	}

	err = writeFile(outputDir+"/decrypt.txt", results.String())
	if err != nil {
		return fmt.Errorf("writing %s/decrypt.txt: %v", outputDir, err)
	}

	fmt.Println("Brute-force completed successfully")
	return nil
}
