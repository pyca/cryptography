package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"io"
	"os"
	"strconv"
	"strings"
)

func unhexlify(s string) []byte {
	bytes, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return bytes
}

func verifier(l uint64, ikm, okm []byte) bool {
	hash := sha256.New
	hkdf := hkdf.New(hash, ikm, nil, nil)
	okmComputed := make([]byte, l)
	io.ReadFull(hkdf, okmComputed)
	return bytes.Equal(okmComputed, okm)
}

func validateVectors(filename string) bool {
	vectors, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer vectors.Close()

	var segments []string
	var l uint64
	var ikm, okm string

	scanner := bufio.NewScanner(vectors)
	for scanner.Scan() {
		segments = strings.Split(scanner.Text(), " = ")

		switch {
		case strings.ToUpper(segments[0]) == "L":
			l, err = strconv.ParseUint(segments[1], 10, 64)
			if err != nil {
				panic(err)
			}
		case strings.ToUpper(segments[0]) == "IKM":
			ikm = segments[1]
		case strings.ToUpper(segments[0]) == "OKM":
			okm = segments[1]
		}
	}
	return verifier(l, unhexlify(ikm), unhexlify(okm))
}

func main() {
	if validateVectors("vectors/cryptography_vectors/KDF/hkdf-generated.txt") {
		fmt.Println("HKDF OK.")
	} else {
		fmt.Println("HKDF failed.")
		os.Exit(1)
	}
}
