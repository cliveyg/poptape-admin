package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
	"os"
	"reflect"
	"strconv"
	"time"
)

//-----------------------------------------------------------------------------

type Claims struct {
	Username string `json:"username"`
	AdminId  string `json:"admin_id"`
	Exp      int64  `json:"exp"`
	jwt.RegisteredClaims
}

//-----------------------------------------------------------------------------

func GenerateHashPassword(password []byte) ([]byte, error) {
	b, err := bcrypt.GenerateFromPassword(password, 14)
	return b, err
}

//-----------------------------------------------------------------------------

func VerifyPassword(bp []byte, hashed []byte) bool {
	err := bcrypt.CompareHashAndPassword(hashed, bp)
	return err == nil
}

//-----------------------------------------------------------------------------

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

//-----------------------------------------------------------------------------

func GenerateToken(username string, adminId uuid.UUID) (string, error) {

	tokenLifespan, err := strconv.Atoi(os.Getenv("TOKEN_LIFESPAN"))
	if err != nil {
		return "", err
	}

	claims := jwt.MapClaims{}
	claims["username"] = username
	claims["admin_id"] = adminId.String()
	// if in DEV env ignore token lifespan and set token to 24h expiry
	if os.Getenv("ENVIRONMENT") == "DEV" {
		claims["exp"] = time.Now().Add(time.Hour * 24).Unix()
	} else {
		claims["exp"] = time.Now().Add(time.Minute * time.Duration(tokenLifespan)).Unix()
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	var rs string
	rs, err = token.SignedString([]byte(os.Getenv("TOKEN_SECRET")))
	if err != nil {
		return "", err
	}
	return rs, nil

}

//-----------------------------------------------------------------------------

func ParseToken(ts string) (*Claims, error) {

	log.Debug().Msgf("Parsing token string [%s]", ts)

	token, err := jwt.ParseWithClaims(ts, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("TOKEN_SECRET")), nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid token claims")

}

//-----------------------------------------------------------------------------

func StructToMap(obj interface{}) map[string]interface{} {
	mp := make(map[string]interface{})
	val := reflect.ValueOf(obj)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	typ := val.Type()
	for i := 0; i < val.NumField(); i++ {
		fieldName := typ.Field(i).Name
		fieldValue := val.Field(i).Interface()
		mp[fieldName] = fieldValue
	}
	return mp
}
