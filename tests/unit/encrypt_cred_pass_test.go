package unit

import (
	"encoding/base64"
	"testing"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/stretchr/testify/assert"
)

func TestEncryptCredPass_HappyPath(t *testing.T) {
	t.Setenv("SUPERSECRETKEY", "0123456789abcdef0123456789abcdef")
	t.Setenv("SUPERSECRETNONCE", "123456789abc")

	rawPassword := "myrealpassword"
	b64 := base64.StdEncoding.EncodeToString([]byte(rawPassword))
	cred := &app.Cred{
		DBPassword: b64,
	}

	err := app.EncryptCredPass(cred)
	assert.NoError(t, err)
	assert.NotEqual(t, b64, cred.DBPassword)
	decoded, err := base64.StdEncoding.DecodeString(cred.DBPassword)
	assert.NoError(t, err)
	assert.NotEmpty(t, decoded)
}

func TestEncryptCredPass_BadBase64(t *testing.T) {
	t.Setenv("SUPERSECRETKEY", "0123456789abcdef0123456789abcdef")
	t.Setenv("SUPERSECRETNONCE", "123456789abc")

	cred := &app.Cred{
		DBPassword: "not_base64",
	}
	err := app.EncryptCredPass(cred)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Base64 decoding failed")
}

func TestEncryptCredPass_MissingEnvKey(t *testing.T) {
	t.Setenv("SUPERSECRETKEY", "")
	t.Setenv("SUPERSECRETNONCE", "123456789abc")

	rawPassword := "pw"
	b64 := base64.StdEncoding.EncodeToString([]byte(rawPassword))
	cred := &app.Cred{
		DBPassword: b64,
	}
	err := app.EncryptCredPass(cred)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SUPERSECRETKEY is missing or blank")
}

func TestEncryptCredPass_MissingEnvNonce(t *testing.T) {
	t.Setenv("SUPERSECRETKEY", "0123456789abcdef0123456789abcdef")
	t.Setenv("SUPERSECRETNONCE", "")

	rawPassword := "pw"
	b64 := base64.StdEncoding.EncodeToString([]byte(rawPassword))
	cred := &app.Cred{
		DBPassword: b64,
	}
	err := app.EncryptCredPass(cred)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SUPERSECRETNONCE is missing or blank")
}

func TestEncryptCredPass_EncryptError(t *testing.T) {
	t.Setenv("SUPERSECRETKEY", "shortkey")
	t.Setenv("SUPERSECRETNONCE", "123456789abc")

	rawPassword := "pw"
	b64 := base64.StdEncoding.EncodeToString([]byte(rawPassword))
	cred := &app.Cred{
		DBPassword: b64,
	}
	err := app.EncryptCredPass(cred)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Encryption failed")
}
