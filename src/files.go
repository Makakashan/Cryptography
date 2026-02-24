package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func readFile(filename string) (string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(content)), nil
}

func writeFile(filename, content string) error {
	return os.WriteFile(filename, []byte(content), 0644)
}

func readKey(filename string) (int, int, error) {
	content, err := readFile(filename)
	if err != nil {
		return 0, 0, err
	}

	parts := strings.Fields(content)
	if len(parts) < 1 {
		return 0, 0, fmt.Errorf("empty key file")
	}

	shift, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid key format")
	}

	a := 0
	if len(parts) >= 2 {
		a, err = strconv.Atoi(parts[1])
		if err != nil {
			return 0, 0, fmt.Errorf("invalid key format")
		}
	}

	return shift, a, nil
}
