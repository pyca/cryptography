package main

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"rc2sucks/rc2"
)

func main() {
	// Generate
	count := 1
	key := []byte("0000000000000000")
	iv := []byte("00000000")
	plaintext := []byte("the quick brown fox jumped over the lazy dog!!!!")
	ciphertext := make([]byte, len(plaintext))
	block, _ := rc2.New(key, 128)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)
	fmt.Printf("COUNT = %v\n", count)
	fmt.Printf("Key = %s\n", hex.EncodeToString(key))
	fmt.Printf("IV = %s\n", hex.EncodeToString(iv))
	fmt.Printf("Plaintext = %s\n", hex.EncodeToString(plaintext))
	fmt.Printf("Ciphertext = %s\n", hex.EncodeToString(ciphertext))
	// Verify
	decrypted := make([]byte, len(plaintext))
	decmode := cipher.NewCBCDecrypter(block, iv)
	decmode.CryptBlocks(decrypted, ciphertext)
	if bytes.Equal(decrypted, plaintext) {
		fmt.Println("Success")
	} else {
		fmt.Println("Failed")
	}
}
