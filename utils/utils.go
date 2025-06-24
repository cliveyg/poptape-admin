package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"os"
	"strconv"
	"time"
)

func GenerateHashPassword(password string) ([]byte, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return b, err
}

func VerifyPassword(password string, hashed []byte) bool {
	bp := []byte(password)
	err := bcrypt.CompareHashAndPassword(hashed, bp)
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

func GenerateToken(username string, adminId uuid.UUID) (string, error) {

	tokenLifespan, err := strconv.Atoi(os.Getenv("TOKEN_LIFESPAN"))
	if err != nil {
		return "", err
	}

	claims := jwt.MapClaims{}
	claims["authorized"] = true
	claims["username"] = username
	claims["admin_id"] = adminId.String()
	claims["exp"] = time.Now().Add(time.Minute * time.Duration(tokenLifespan)).Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	var rs string
	rs, err = token.SignedString([]byte(os.Getenv("TOKEN_SECRET")))
	if err != nil {
		return "", err
	}
	return rs, nil

}
