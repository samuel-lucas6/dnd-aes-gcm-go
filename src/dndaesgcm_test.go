package dndaesgcm_test

import (
	"bytes"
	"dndaesgcm"
	"encoding/hex"
	"testing"
)

type params struct {
	ciphertext     string
	plaintext      string
	nonce          string
	key            string
	associatedData string
}

var testVector = params{
	ciphertext:     "fe81aa54b08927b8a6d070a0bb1a365f32ba00b7096b19f9da95e6c716b0cf05690e105ac22d43ae9032afdf4010b6f566ecc26b8bbc76932dfc9dd60921d8e4fe94f5b0b6233d2b94e44c35231b435cbb8a46a242c13bc530858411cd7534e3582b54179eaf31cd7b57cd9cd09cabd370549d699eae42d334553d8076e65fc21226",
	plaintext:      "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
	nonce:          "404142434445464748494a4b4c4d4e4f5051525354555657",
	key:            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
	associatedData: "50515253c0c1c2c3c4c5c6c7",
}

func TestConstantsValid(t *testing.T) {
	if dndaesgcm.KeySize != 32 {
		t.Errorf("KeySize should be 32")
	}
	if dndaesgcm.NonceSize != 24 {
		t.Errorf("NonceSize should be 24")
	}
	if dndaesgcm.TagSize != 16 {
		t.Errorf("TagSize should be 16")
	}
}

func TestEncryptValid(t *testing.T) {
	expected, _ := hex.DecodeString(testVector.ciphertext)
	plaintext, _ := hex.DecodeString(testVector.plaintext)
	nonce, _ := hex.DecodeString(testVector.nonce)
	key, _ := hex.DecodeString(testVector.key)
	associatedData, _ := hex.DecodeString(testVector.associatedData)
	actual, _ := dndaesgcm.Encrypt(plaintext, nonce, key, associatedData)
	if !bytes.Equal(expected, actual) {
		t.Errorf("ciphertext doesn't match")
	}
}

func TestEncryptInvalid(t *testing.T) {
	parameters := []struct {
		plaintextSize      int
		nonceSize          int
		keySize            int
		associatedDataSize int
	}{
		{0, dndaesgcm.NonceSize + 1, dndaesgcm.KeySize, 0},
		{0, dndaesgcm.NonceSize - 1, dndaesgcm.KeySize, 0},
		{0, dndaesgcm.NonceSize, dndaesgcm.KeySize + 1, 0},
		{0, dndaesgcm.NonceSize, dndaesgcm.KeySize - 1, 0},
	}

	for _, parameter := range parameters {
		t.Run("", func(t *testing.T) {
			plaintext := make([]byte, parameter.plaintextSize)
			nonce := make([]byte, parameter.nonceSize)
			key := make([]byte, parameter.keySize)
			associatedData := make([]byte, parameter.associatedDataSize)
			ciphertext, err := dndaesgcm.Encrypt(plaintext, nonce, key, associatedData)
			if err == nil {
				t.Errorf("encrypt should fail")
			}
			if ciphertext != nil {
				t.Errorf("ciphertext should be nil")
			}
		})
	}
}

func TestDecryptValid(t *testing.T) {
	expected, _ := hex.DecodeString(testVector.plaintext)
	ciphertext, _ := hex.DecodeString(testVector.ciphertext)
	nonce, _ := hex.DecodeString(testVector.nonce)
	key, _ := hex.DecodeString(testVector.key)
	associatedData, _ := hex.DecodeString(testVector.associatedData)
	actual, _ := dndaesgcm.Decrypt(ciphertext, nonce, key, associatedData)
	if !bytes.Equal(expected, actual) {
		t.Errorf("plaintext doesn't match")
	}
}

func TestDecryptTampered(t *testing.T) {
	hexDecode := func(s string) []byte {
		decoded, _ := hex.DecodeString(s)
		return decoded
	}

	parameters := [][]byte{
		hexDecode(testVector.ciphertext),
		hexDecode(testVector.nonce),
		hexDecode(testVector.key),
		hexDecode(testVector.associatedData),
	}
	for i := 0; i < len(parameters); i++ {
		if parameters[i] == nil {
			continue
		}
		parameters[i][0]++
		plaintext, err := dndaesgcm.Decrypt(parameters[0], parameters[1], parameters[2], parameters[3])
		parameters[i][0]--
		if err == nil {
			t.Errorf("decrypt should fail")
		}
		if plaintext != nil {
			t.Errorf("plaintext should be nil")
		}
	}
}

func TestDecryptInvalid(t *testing.T) {
	parameters := []struct {
		ciphertextSize     int
		nonceSize          int
		keySize            int
		associatedDataSize int
	}{
		{dndaesgcm.TagSize - 1, dndaesgcm.NonceSize, dndaesgcm.KeySize, 0},
		{dndaesgcm.TagSize, dndaesgcm.NonceSize + 1, dndaesgcm.KeySize, 0},
		{dndaesgcm.TagSize, dndaesgcm.NonceSize - 1, dndaesgcm.KeySize, 0},
		{dndaesgcm.TagSize, dndaesgcm.NonceSize, dndaesgcm.KeySize + 1, 0},
		{dndaesgcm.TagSize, dndaesgcm.NonceSize, dndaesgcm.KeySize - 1, 0},
	}

	for _, parameter := range parameters {
		t.Run("", func(t *testing.T) {
			ciphertext := make([]byte, parameter.ciphertextSize)
			nonce := make([]byte, parameter.nonceSize)
			key := make([]byte, parameter.keySize)
			associatedData := make([]byte, parameter.associatedDataSize)
			plaintext, err := dndaesgcm.Decrypt(ciphertext, nonce, key, associatedData)
			if err == nil {
				t.Errorf("decrypt should fail")
			}
			if plaintext != nil {
				t.Errorf("plaintext should be nil")
			}
		})
	}
}
