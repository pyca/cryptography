package main

import (
	"bufio"
	"bytes"
	"crypto/rc4"
	"encoding/hex"
	"fmt"
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

type vectorArgs struct {
	count      string
	offset     uint64
	key        string
	plaintext  string
	ciphertext string
}

type vectorVerifier interface {
	validate(count string, offset uint64, key, plaintext, expectedCiphertext []byte)
}

type arc4Verifier struct{}

func (o arc4Verifier) validate(count string, offset uint64, key, plaintext, expectedCiphertext []byte) {
	if offset%16 != 0 || len(plaintext) != 16 || len(expectedCiphertext) != 16 {
		panic(fmt.Errorf("Unexpected input value encountered: offset=%v; len(plaintext)=%v; len(expectedCiphertext)=%v",
			offset,
			len(plaintext),
			len(expectedCiphertext)))
	}
	stream, err := rc4.NewCipher(key)
	if err != nil {
		panic(err)
	}

	var currentOffset uint64 = 0
	ciphertext := make([]byte, len(plaintext))
	for currentOffset <= offset {
		stream.XORKeyStream(ciphertext, plaintext)
		currentOffset += uint64(len(plaintext))
	}
	if !bytes.Equal(ciphertext, expectedCiphertext) {
		panic(fmt.Errorf("vector mismatch @ COUNT = %s:\n  %s != %s\n",
			count,
			hex.EncodeToString(expectedCiphertext),
			hex.EncodeToString(ciphertext)))
	}
}

func validateVectors(verifier vectorVerifier, filename string) {
	vectors, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer vectors.Close()

	var segments []string
	var vector *vectorArgs

	scanner := bufio.NewScanner(vectors)
	for scanner.Scan() {
		segments = strings.Split(scanner.Text(), " = ")

		switch {
		case strings.ToUpper(segments[0]) == "COUNT":
			if vector != nil {
				verifier.validate(vector.count,
					vector.offset,
					unhexlify(vector.key),
					unhexlify(vector.plaintext),
					unhexlify(vector.ciphertext))
			}
			vector = &vectorArgs{count: segments[1]}
		case strings.ToUpper(segments[0]) == "OFFSET":
			vector.offset, err = strconv.ParseUint(segments[1], 10, 64)
			if err != nil {
				panic(err)
			}
		case strings.ToUpper(segments[0]) == "KEY":
			vector.key = segments[1]
		case strings.ToUpper(segments[0]) == "PLAINTEXT":
			vector.plaintext = segments[1]
		case strings.ToUpper(segments[0]) == "CIPHERTEXT":
			vector.ciphertext = segments[1]
		}
	}
	if vector != nil {
		verifier.validate(vector.count,
			vector.offset,
			unhexlify(vector.key),
			unhexlify(vector.plaintext),
			unhexlify(vector.ciphertext))
	}
}

func main() {
	validateVectors(arc4Verifier{}, "vectors/cryptography_vectors/ciphers/ARC4/arc4.txt")
	fmt.Println("ARC4 OK.")
}
