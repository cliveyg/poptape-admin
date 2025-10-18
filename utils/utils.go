package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"os"
	"regexp"
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

//-----------------------------------------------------------------------------

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

// enables easier testing
var GenerateToken = generateToken

func generateToken(username string, adminId uuid.UUID) (string, error) {

	tokenLifespan, err := strconv.Atoi(os.Getenv("TOKEN_LIFESPAN"))
	if err != nil {
		return "", err
	}
	secret := os.Getenv("TOKEN_SECRET")
	if secret == "" {
		return "", errors.New("TOKEN_SECRET not set")
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
	rs, err = token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}
	return rs, nil

}

//-----------------------------------------------------------------------------

var ParseToken = parseToken

func parseToken(ts string) (*Claims, error) {

	//log.Debug().Msgf("Parsing token string [%s]", ts)

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

func ValidDataInput(inSt string) error {
	if inSt == "" {
		return nil
	}
	var validName = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	if !validName.MatchString(inSt) {
		return errors.New("invalid data input - incorrect chars")
	}
	if len(inSt) > 30 || len(inSt) < 4 {
		return errors.New("invalid data input - too long")
	}
	return nil
}

//-----------------------------------------------------------------------------

// we run this func before parsing as it's stricter than the parser
func IsValidUUIDString(s string) bool {
	var uuidRegex = regexp.MustCompile("^[a-fA-F0-9]{8}\\-[a-fA-F0-9]{4}\\-[a-fA-F0-9]{4}\\-[a-fA-F0-9]{4}\\-[a-fA-F0-9]{12}$")
	return uuidRegex.MatchString(s)
}

//-----------------------------------------------------------------------------

func IsAcceptedString(s string) bool {
	var uuidRegex = regexp.MustCompile("^[a-z_]+$")
	return uuidRegex.MatchString(s)
}
