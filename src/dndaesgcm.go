package dndaesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
)

const (
	KeySize   = 32
	NonceSize = 24
	TagSize   = 16
)

func Encrypt(plaintext []byte, nonce []byte, key []byte, associatedData []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, errors.New("nonce length must equal NonceSize")
	}
	if len(key) != KeySize {
		return nil, errors.New("key length must equal KeySize")
	}

	subkey := derive(key, nonce)
	blockCipher, _ := aes.NewCipher(subkey)
	gcm, _ := cipher.NewGCM(blockCipher)
	emptyNonce := make([]byte, gcm.NonceSize())
	return gcm.Seal(nil, emptyNonce, plaintext, associatedData), nil
}

func Decrypt(ciphertext []byte, nonce []byte, key []byte, associatedData []byte) ([]byte, error) {
	if len(ciphertext) < TagSize {
		return nil, errors.New("ciphertext length must be at least TagSize")
	}
	if len(nonce) != NonceSize {
		return nil, errors.New("nonce length must equal NonceSize")
	}
	if len(key) != KeySize {
		return nil, errors.New("key length must equal KeySize")
	}

	subkey := derive(key, nonce)
	blockCipher, _ := aes.NewCipher(subkey)
	gcm, _ := cipher.NewGCM(blockCipher)
	emptyNonce := make([]byte, gcm.NonceSize())
	return gcm.Open(nil, emptyNonce, ciphertext, associatedData)
}

func derive(key []byte, nonce []byte) []byte {
	subkey := make([]byte, KeySize)
	temp := make([]byte, aes.BlockSize)
	message := make([]byte, aes.BlockSize)
	blockCipher, _ := aes.NewCipher(key)

	copy(message, nonce[:12])
	message[len(message)-1] = 0x01
	blockCipher.Encrypt(subkey[:16], message)
	message[len(message)-1] = 0x02
	blockCipher.Encrypt(temp, message)
	subtle.XORBytes(subkey[:16], subkey[:16], temp)
	message[len(message)-1] = 0x03
	blockCipher.Encrypt(temp, message)
	subtle.XORBytes(subkey[:16], subkey[:16], temp)

	copy(message, nonce[12:])
	message[len(message)-1] = 0x04
	blockCipher.Encrypt(subkey[16:], message)
	message[len(message)-1] = 0x05
	blockCipher.Encrypt(temp, message)
	subtle.XORBytes(subkey[16:], subkey[16:], temp)
	message[len(message)-1] = 0x06
	blockCipher.Encrypt(temp, message)
	subtle.XORBytes(subkey[16:], subkey[16:], temp)
	return subkey
}
