package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	origFile    = "orig.txt"
	plainFile   = "plain.txt"
	keyFile     = "key.txt"
	cryptoFile  = "crypto.txt"
	decryptFile = "decrypt.txt"

	lineLen = 64
)

// Allowed plaintext chars for this assignment:
func isAllowedPlainChar(b byte) bool {
	return b == ' ' || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func isLetter(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// xorHasSpacePattern checks top two bits == 01 for 7-bit ASCII assumption.
func xorHasSpacePattern(x byte) bool {
	return (x&0x80) == 0 && (x&0x40) != 0
}

func main() {
	prepare := flag.Bool("p", false, "prepare plaintext: orig.txt -> plain.txt (64 chars per line)")
	encrypt := flag.Bool("e", false, "encrypt plain.txt with key.txt -> crypto.txt")
	cryptanalysis := flag.Bool("k", false, "cryptanalysis from crypto.txt -> decrypt.txt")
	flag.Parse()

	modeCount := 0
	if *prepare {
		modeCount++
	}
	if *encrypt {
		modeCount++
	}
	if *cryptanalysis {
		modeCount++
	}
	if modeCount != 1 {
		exitErr(errors.New("choose exactly one mode: -p or -e or -k"))
	}

	var err error
	switch {
	case *prepare:
		err = runPrepare()
	case *encrypt:
		err = runEncrypt()
	case *cryptanalysis:
		err = runCryptanalysis()
	}

	if err != nil {
		exitErr(err)
	}
}

func exitErr(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

// Reads orig.txt, keeps only letters/spaces, normalizes whitespace to single spaces,
// then writes plain.txt as lines of exactly 64 characters.
func runPrepare() error {
	raw, err := os.ReadFile(origFile)
	if err != nil {
		return fmt.Errorf("read %s: %w", origFile, err)
	}

	normalized := normalizeToLettersAndSpaces(raw)
	if len(normalized) == 0 {
		return fmt.Errorf("%s has no usable letters/spaces after normalization", origFile)
	}

	lines := splitIntoFixedLines(normalized, lineLen, true)
	out := strings.Join(lines, "\n")
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}

	if err := os.WriteFile(plainFile, []byte(out), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", plainFile, err)
	}
	return nil
}

func normalizeToLettersAndSpaces(data []byte) []byte {
	var out []byte
	prevSpace := true // avoid leading spaces

	for _, b := range data {
		switch {
		case isLetter(b):
			out = append(out, b)
			prevSpace = false
		case b == ' ' || b == '\t' || b == '\r' || b == '\n':
			if !prevSpace {
				out = append(out, ' ')
				prevSpace = true
			}
		default:
			// skip everything else
		}
	}

	// trim trailing space
	for len(out) > 0 && out[len(out)-1] == ' ' {
		out = out[:len(out)-1]
	}
	return out
}

func splitIntoFixedLines(data []byte, width int, padLast bool) []string {
	if width <= 0 {
		return nil
	}
	var lines []string
	for i := 0; i < len(data); i += width {
		end := i + width
		if end <= len(data) {
			lines = append(lines, string(data[i:end]))
			continue
		}
		last := append([]byte{}, data[i:]...)
		if padLast {
			for len(last) < width {
				last = append(last, ' ')
			}
			lines = append(lines, string(last))
		} else {
			lines = append(lines, string(last))
		}
	}
	return lines
}

// Output written to crypto.txt as HEX text (1 line = 128 hex chars).
func runEncrypt() error {
	key, err := readOrCreateKey(keyFile, lineLen)
	if err != nil {
		return err
	}
	if len(key) != lineLen {
		return fmt.Errorf("%s must be exactly %d bytes", keyFile, lineLen)
	}

	plain, err := os.ReadFile(plainFile)
	if err != nil {
		return fmt.Errorf("read %s: %w", plainFile, err)
	}

	plainLines, err := parseTextLinesExactWidth(plain, lineLen)
	if err != nil {
		return fmt.Errorf("%s invalid: %w", plainFile, err)
	}
	if len(plainLines) == 0 {
		return fmt.Errorf("%s has no lines to encrypt", plainFile)
	}

	var out bytes.Buffer
	for i, line := range plainLines {
		// Validate assignment alphabet restriction
		for j := 0; j < len(line); j++ {
			if !isAllowedPlainChar(line[j]) {
				return fmt.Errorf("%s line %d has disallowed char at pos %d (byte=%d)", plainFile, i+1, j+1, line[j])
			}
		}

		c := xorBytes(line, key)
		hexLine := make([]byte, hex.EncodedLen(len(c)))
		hex.Encode(hexLine, c)

		out.Write(hexLine)
		out.WriteByte('\n')
	}

	if err := os.WriteFile(cryptoFile, out.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", cryptoFile, err)
	}
	return nil
}

func readOrCreateKey(path string, n int) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err == nil {
		// If text editor added trailing newline and total is n+1, trim one '\n'
		if len(key) == n+1 && key[n] == '\n' {
			key = key[:n]
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	key = make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate random key: %w", err)
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, fmt.Errorf("write %s: %w", path, err)
	}
	return key, nil
}

// Uses only crypto.txt (ciphertexts encrypted with same key).
func runCryptanalysis() error {
	cipherLines, err := parseHexCipherLinesExactWidth(cryptoFile, lineLen)
	if err != nil {
		return fmt.Errorf("%s invalid: %w", cryptoFile, err)
	}
	if len(cipherLines) == 0 {
		return fmt.Errorf("%s has no ciphertext lines", cryptoFile)
	}

	keyGuess := make([]byte, lineLen)
	keyKnown := make([]bool, lineLen)

	n := len(cipherLines)
	threshold := max(1, (n-1)/2)

	for pos := 0; pos < lineLen; pos++ {
		for i := 0; i < n; i++ {
			score := 0
			for j := 0; j < n; j++ {
				if i == j {
					continue
				}
				x := cipherLines[i][pos] ^ cipherLines[j][pos]
				if xorHasSpacePattern(x) {
					score++
				}
			}
			if score >= threshold {
				kg := cipherLines[i][pos] ^ byte(' ')
				if !keyKnown[pos] {
					keyGuess[pos] = kg
					keyKnown[pos] = true
				} else if keyGuess[pos] != kg {
				}
			}
		}
	}

	var out bytes.Buffer
	for _, c := range cipherLines {
		plain := make([]byte, lineLen)
		for i := 0; i < lineLen; i++ {
			if keyKnown[i] {
				p := c[i] ^ keyGuess[i]
				if isAllowedPlainChar(p) {
					plain[i] = p
				} else {
					plain[i] = '_'
				}
			} else {
				plain[i] = '_'
			}
		}
		out.Write(plain)
		out.WriteByte('\n')
	}

	if err := os.WriteFile(decryptFile, out.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", decryptFile, err)
	}
	return nil
}

func xorBytes(a, b []byte) []byte {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// parseTextLinesExactWidth parses textual lines, strips final '\r', ignores empty last line,
func parseTextLinesExactWidth(data []byte, width int) ([][]byte, error) {
	rawLines := bytes.Split(data, []byte{'\n'})
	lines := make([][]byte, 0, len(rawLines))

	for idx, ln := range rawLines {
		if len(ln) == 0 {
			// allow trailing empty line
			if idx == len(rawLines)-1 {
				continue
			}
			// skip accidental empty lines
			continue
		}
		if ln[len(ln)-1] == '\r' {
			ln = ln[:len(ln)-1]
		}
		if len(ln) != width {
			return nil, fmt.Errorf("line %d has length %d, expected %d", idx+1, len(ln), width)
		}
		lines = append(lines, append([]byte{}, ln...))
	}
	return lines, nil
}

// parseHexCipherLinesExactWidth reads crypto.txt where each line is hex-encoded ciphertext.
func parseHexCipherLinesExactWidth(path string, width int) ([][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	// max hex line length for width bytes is width*2, add margin
	buf := make([]byte, 0, width*2+16)
	sc.Buffer(buf, 1024*1024)

	var lines [][]byte
	lineNo := 0
	for sc.Scan() {
		lineNo++
		s := strings.TrimSpace(sc.Text())
		if s == "" {
			continue
		}
		if len(s) != width*2 {
			return nil, fmt.Errorf("cipher line %d has hex length %d, expected %d", lineNo, len(s), width*2)
		}
		decoded, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("cipher line %d is not valid hex: %w", lineNo, err)
		}
		if len(decoded) != width {
			return nil, fmt.Errorf("cipher line %d decodes to %d bytes, expected %d", lineNo, len(decoded), width)
		}
		lines = append(lines, decoded)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}
