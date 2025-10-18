package unit

import (
	"github.com/cliveyg/poptape-admin/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
	"time"
)

//-----------------------------------------------------------------------------
// Fully independent tests for the utils package
//-----------------------------------------------------------------------------

// --- helpers ---
func SetEnv(envs map[string]string) func() {
	originals := make(map[string]string)
	for k := range envs {
		originals[k] = os.Getenv(k)
	}
	for k, v := range envs {
		os.Setenv(k, v)
	}
	return func() {
		for k, v := range originals {
			os.Setenv(k, v)
		}
	}
}

// --- GenerateHashPassword ---
func TestGenerateHashPassword_HappyPath(t *testing.T) {
	pwd := []byte("password123")
	hashed, err := utils.GenerateHashPassword(pwd)
	assert.NoError(t, err)
	assert.NotEmpty(t, hashed)
	assert.NotEqual(t, string(pwd), string(hashed))
}

// --- VerifyPassword ---
func TestVerifyPassword_HappyPath(t *testing.T) {
	pwd := []byte("password123")
	hashed, _ := utils.GenerateHashPassword(pwd)
	ok := utils.VerifyPassword(pwd, hashed)
	assert.True(t, ok)
}

func TestVerifyPassword_Error(t *testing.T) {
	pwd := []byte("password123")
	hashed, _ := utils.GenerateHashPassword([]byte("otherpassword"))
	ok := utils.VerifyPassword(pwd, hashed)
	assert.False(t, ok)
}

// --- Encrypt/Decrypt ---

func TestEncryptDecrypt_HappyPath(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes for AES-256
	nonce := []byte("123456789abc")                   // 12 bytes for GCM
	plain := []byte("hello world")

	assert.Equal(t, 12, len(nonce), "nonce must be 12 bytes")

	enc, err := utils.Encrypt(plain, key, nonce)
	assert.NoError(t, err)
	assert.NotEmpty(t, enc)

	dec, err := utils.Decrypt(enc, key, nonce)
	assert.NoError(t, err)
	assert.Equal(t, plain, dec)
}

func TestEncrypt_ErrorCases(t *testing.T) {
	plain := []byte("data")
	key := []byte("shortkey")       // too short for AES
	nonce := []byte("123456789abc") // 12 bytes for GCM

	assert.Equal(t, 12, len(nonce), "nonce must be 12 bytes")

	enc, err := utils.Encrypt(plain, key, nonce)
	assert.Error(t, err)
	assert.Empty(t, enc)
}

func TestDecrypt_ErrorCases(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	nonce := []byte("123456789abc") // 12 bytes

	assert.Equal(t, 12, len(nonce), "nonce must be 12 bytes")

	// not valid base64
	_, err := utils.Decrypt("not_base64!", key, nonce)
	assert.Error(t, err)

	// valid base64 but wrong key
	plain := []byte("hello world")
	enc, _ := utils.Encrypt(plain, key, nonce)
	wrongKey := []byte("0123456789abcdef0123456789abc0")
	_, err = utils.Decrypt(enc, wrongKey, nonce)
	assert.Error(t, err)

	// valid base64 but wrong nonce (must be 12 bytes, just different value)
	wrongNonce := []byte("abcdefghijkl") // 12 bytes
	assert.Equal(t, 12, len(wrongNonce), "wrongNonce must be 12 bytes")
	_, err = utils.Decrypt(enc, key, wrongNonce)
	assert.Error(t, err)
}

// --- GenerateToken/ParseToken ---
func TestGenerateToken_And_ParseToken_HappyPath(t *testing.T) {
	adminID := uuid.New()
	cleanup := SetEnv(map[string]string{
		"TOKEN_SECRET":   "s3cr3tkeyforjwt",
		"TOKEN_LIFESPAN": "60",
		"ENVIRONMENT":    "PROD",
	})
	defer cleanup()

	token, err := utils.GenerateToken("alice", adminID)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	claims, err := utils.ParseToken(token)
	assert.NoError(t, err)
	assert.Equal(t, "alice", claims.Username)
	assert.Equal(t, adminID.String(), claims.AdminId)
	assert.True(t, claims.Exp > time.Now().Unix())
}

func TestGenerateToken_ErrorCases(t *testing.T) {
	adminID := uuid.New()
	// Missing TOKEN_LIFESPAN (should error)
	cleanup := SetEnv(map[string]string{
		"TOKEN_SECRET": "s3cr3tkeyforjwt",
		"ENVIRONMENT":  "PROD",
	})
	defer cleanup()
	_, err := utils.GenerateToken("bob", adminID)
	assert.Error(t, err)

	// Missing TOKEN_SECRET (should error)
	cleanup2 := SetEnv(map[string]string{
		"TOKEN_LIFESPAN": "60",
		"ENVIRONMENT":    "PROD",
	})
	defer cleanup2()
	os.Unsetenv("TOKEN_SECRET") // Ensure TOKEN_SECRET is truly unset
	_, err = utils.GenerateToken("bob", adminID)
	assert.Error(t, err)
}

func TestParseToken_ErrorCases(t *testing.T) {
	cleanup := SetEnv(map[string]string{
		"TOKEN_SECRET": "s3cr3tkeyforjwt",
	})
	defer cleanup()

	// Malformed token
	_, err := utils.ParseToken("not_a_token")
	assert.Error(t, err)

	// Token with wrong secret
	adminID := uuid.New()
	SetEnv(map[string]string{
		"TOKEN_SECRET":   "rightsecret",
		"TOKEN_LIFESPAN": "1",
		"ENVIRONMENT":    "PROD",
	})()
	token, _ := utils.GenerateToken("carol", adminID)
	SetEnv(map[string]string{
		"TOKEN_SECRET": "wrongsecret",
	})()
	_, err = utils.ParseToken(token)
	assert.Error(t, err)
}

// --- ValidDataInput ---
func TestValidDataInput_HappyPath(t *testing.T) {
	assert.NoError(t, utils.ValidDataInput("validInput123"))
	assert.NoError(t, utils.ValidDataInput("user_ABC"))
}

func TestValidDataInput_ErrorCases(t *testing.T) {
	assert.Error(t, utils.ValidDataInput("invalid!chars"))
	assert.Error(t, utils.ValidDataInput("sh"))                                          // too short
	assert.Error(t, utils.ValidDataInput("waytoolonginputstringthatexceedsthirtychars")) // too long
}

// --- IsValidUUIDString ---
func TestIsValidUUIDString(t *testing.T) {
	assert.True(t, utils.IsValidUUIDString(uuid.New().String()))
	assert.False(t, utils.IsValidUUIDString("not-a-uuid"))
	assert.False(t, utils.IsValidUUIDString("123456"))
}

// --- IsAcceptedString ---
func TestIsAcceptedString(t *testing.T) {
	assert.True(t, utils.IsAcceptedString("foo_bar"))
	assert.True(t, utils.IsAcceptedString("foo"))
	assert.False(t, utils.IsAcceptedString("fooBar"))
	assert.False(t, utils.IsAcceptedString("foo-bar"))
	assert.False(t, utils.IsAcceptedString("foo123"))
}
