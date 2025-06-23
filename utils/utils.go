package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"golang.org/x/crypto/bcrypt"
)

func GenerateHashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func VerifyPassword(password string, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func Encrypt(ptext []byte, key []byte, nonce []byte) (string, error) {

	// encrypt the byte array and base64 encode the encrypted byte array
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	var aesgcm cipher.AEAD
	aesgcm, err = cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext := aesgcm.Seal(nil, nonce, ptext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func Decrypt(ciphertext string, key []byte, nonce []byte) ([]byte, error) {

	// base64 decode the string into a byte array and decrypt;
	// return the decrypted byte array
	var err error
	var decoded []byte
	decoded, err = base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}

	var block cipher.Block
	block, err = aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	var aesgcm cipher.AEAD
	aesgcm, err = cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	var plaintext []byte
	plaintext, err = aesgcm.Open(nil, nonce, decoded, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
