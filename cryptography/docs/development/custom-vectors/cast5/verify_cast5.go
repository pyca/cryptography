package main

import (
	"bufio"
	"bytes"
	"code.google.com/p/go.crypto/cast5"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"os"
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
	key        string
	iv         string
	plaintext  string
	ciphertext string
}

type vectorVerifier interface {
	validate(count string, key, iv, plaintext, expectedCiphertext []byte)
}

type ofbVerifier struct{}

func (o ofbVerifier) validate(count string, key, iv, plaintext, expectedCiphertext []byte) {
	block, err := cast5.NewCipher(key)
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, len(plaintext))
	stream := cipher.NewOFB(block, iv)
	stream.XORKeyStream(ciphertext, plaintext)

	if !bytes.Equal(ciphertext, expectedCiphertext) {
		panic(fmt.Errorf("vector mismatch @ COUNT = %s:\n  %s != %s\n",
			count,
			hex.EncodeToString(expectedCiphertext),
			hex.EncodeToString(ciphertext)))
	}
}

type cbcVerifier struct{}

func (o cbcVerifier) validate(count string, key, iv, plaintext, expectedCiphertext []byte) {
	block, err := cast5.NewCipher(key)
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	if !bytes.Equal(ciphertext, expectedCiphertext) {
		panic(fmt.Errorf("vector mismatch @ COUNT = %s:\n  %s != %s\n",
			count,
			hex.EncodeToString(expectedCiphertext),
			hex.EncodeToString(ciphertext)))
	}
}

type cfbVerifier struct{}

func (o cfbVerifier) validate(count string, key, iv, plaintext, expectedCiphertext []byte) {
	block, err := cast5.NewCipher(key)
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, len(plaintext))
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext, plaintext)

	if !bytes.Equal(ciphertext, expectedCiphertext) {
		panic(fmt.Errorf("vector mismatch @ COUNT = %s:\n  %s != %s\n",
			count,
			hex.EncodeToString(expectedCiphertext),
			hex.EncodeToString(ciphertext)))
	}
}

type ctrVerifier struct{}

func (o ctrVerifier) validate(count string, key, iv, plaintext, expectedCiphertext []byte) {
	block, err := cast5.NewCipher(key)
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, len(plaintext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, plaintext)

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
					unhexlify(vector.key),
					unhexlify(vector.iv),
					unhexlify(vector.plaintext),
					unhexlify(vector.ciphertext))
			}
			vector = &vectorArgs{count: segments[1]}
		case strings.ToUpper(segments[0]) == "IV":
			vector.iv = segments[1][:16]
		case strings.ToUpper(segments[0]) == "KEY":
			vector.key = segments[1]
		case strings.ToUpper(segments[0]) == "PLAINTEXT":
			vector.plaintext = segments[1]
		case strings.ToUpper(segments[0]) == "CIPHERTEXT":
			vector.ciphertext = segments[1]
		}
	}

}

func main() {
	validateVectors(ofbVerifier{},
		"vectors/cryptography_vectors/ciphers/CAST5/cast5-ofb.txt")
	fmt.Println("OFB OK.")
	validateVectors(cfbVerifier{},
		"vectors/cryptography_vectors/ciphers/CAST5/cast5-cfb.txt")
	fmt.Println("CFB OK.")
	validateVectors(cbcVerifier{},
		"vectors/cryptography_vectors/ciphers/CAST5/cast5-cbc.txt")
	fmt.Println("CBC OK.")
	validateVectors(ctrVerifier{},
		"vectors/cryptography_vectors/ciphers/CAST5/cast5-ctr.txt")
	fmt.Println("CTR OK.")
}
