package tests

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/cliveyg/poptape-admin/utils"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/stretchr/testify/require"
)

// Helper: login as the given user and return JWT token string
func loginAndGetToken(t *testing.T, testApp *app.App, username, password string) string {
	loginReq := map[string]string{
		"username": username,
		"password": password,
	}
	body, _ := json.Marshal(loginReq)
	req, err := http.NewRequest("POST", "/admin/login", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	testApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, "login should return 200")

	var out struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&out))
	require.NotEmpty(t, out.Token)
	return out.Token
}

// Helper: set Validated=true for a user in the DB using testApp.DB
func setUserValidated(t *testing.T, testApp *app.App, username string) {
	result := testApp.DB.Model(&app.User{}).Where("username = ?", username).Update("validated", true)
	require.NoError(t, result.Error)
}

func RandString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[int64(len(letters))*int64(os.Getpid()+i)%int64(len(letters))]
	}
	return string(b)
}

func TestSuperuserLogin(t *testing.T) {
	resetDB(t, TestApp)

	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS") // Already base64 encoded!
	require.NotEmpty(t, superUser, "SUPERUSER env var must be set")
	require.NotEmpty(t, superPass, "SUPERPASS env var must be set")

	loginReq := map[string]string{
		"username": superUser,
		"password": superPass,
	}
	body, _ := json.Marshal(loginReq)
	req, err := http.NewRequest("POST", "/admin/login", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, "superuser login should return 200")

	var out struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&out))
	require.NotEmpty(t, out.Token)
}

func TestUserCRUD_HappyPath(t *testing.T) {
	resetDB(t, TestApp)

	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser, "SUPERUSER env var must be set")
	require.NotEmpty(t, superPass, "SUPERPASS env var must be set")

	token := loginAndGetToken(t, TestApp, superUser, superPass)

	// 1. Create a new user
	userUsername := "testuser1_" + RandString(8)
	userPassword := "testpass1"
	userReq := map[string]string{
		"username":         userUsername,
		"password":         base64.StdEncoding.EncodeToString([]byte(userPassword)),
		"confirm_password": base64.StdEncoding.EncodeToString([]byte(userPassword)),
	}
	body, _ := json.Marshal(userReq)
	req, err := http.NewRequest("POST", "/admin/user", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "user create should return 201")

	// 2. Validate user in DB
	setUserValidated(t, TestApp, userUsername)

	// 3. Login as new user
	loginReq := map[string]string{
		"username": userUsername,
		"password": base64.StdEncoding.EncodeToString([]byte(userPassword)),
	}
	body, _ = json.Marshal(loginReq)
	req2, err := http.NewRequest("POST", "/admin/login", bytes.NewReader(body))
	require.NoError(t, err)
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w2, req2)
	require.Equal(t, http.StatusOK, w2.Code, "login as new user should return 200")
}

func TestSuperuserLogin_Fail_MissingFields(t *testing.T) {
	resetDB(t, TestApp)

	superUser := os.Getenv("SUPERUSER")
	require.NotEmpty(t, superUser, "SUPERUSER env var must be set")

	loginReq := map[string]string{
		"username": superUser,
	}
	body, _ := json.Marshal(loginReq)
	req, err := http.NewRequest("POST", "/admin/login", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code, "login with missing password field return 400")

	var resp map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Contains(t, resp, "message")
	require.Equal(t, "Bad request", resp["message"])

}

func TestSuperuserLogin_Fail_WrongPassword(t *testing.T) {
	resetDB(t, TestApp)

	superUser := os.Getenv("SUPERUSER")
	require.NotEmpty(t, superUser, "SUPERUSER env var must be set")

	loginReq := map[string]string{
		"username": superUser,
		"password": base64.StdEncoding.EncodeToString([]byte("not_the_right_password")), // Intentionally wrong
	}
	body, _ := json.Marshal(loginReq)
	req, err := http.NewRequest("POST", "/admin/login", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code, "login with wrong password should return 401")
}

func TestUserLogin_Fail_WrongPassword(t *testing.T) {
	resetDB(t, TestApp)

	// Setup: create and validate a user
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser, "SUPERUSER env var must be set")
	require.NotEmpty(t, superPass, "SUPERPASS env var must be set")
	token := loginAndGetToken(t, TestApp, superUser, superPass)

	userUsername := "testuser1_fail_" + RandString(8)
	userPassword := "testpass1_fail"
	userReq := map[string]string{
		"username":         userUsername,
		"password":         base64.StdEncoding.EncodeToString([]byte(userPassword)),
		"confirm_password": base64.StdEncoding.EncodeToString([]byte(userPassword)),
	}
	body, _ := json.Marshal(userReq)
	req, err := http.NewRequest("POST", "/admin/user", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "user create should return 201")

	setUserValidated(t, TestApp, userUsername)

	// Now: try logging in with wrong password
	loginReq := map[string]string{
		"username": userUsername,
		"password": base64.StdEncoding.EncodeToString([]byte("wrongpass")),
	}
	body, _ = json.Marshal(loginReq)
	req2, err := http.NewRequest("POST", "/admin/login", bytes.NewReader(body))
	require.NoError(t, err)
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w2, req2)
	require.Equal(t, http.StatusUnauthorized, w2.Code, "login with wrong password should return 401")
}

// --- Failure tests for CreateUser (handlers.go) ---

func TestCreateUser_Fail_BadJSON(t *testing.T) {
	resetDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := loginAndGetToken(t, TestApp, superUser, superPass)

	// Send invalid JSON
	req, err := http.NewRequest("POST", "/admin/user", bytes.NewBufferString("{invalid-json}"))
	require.NoError(t, err)
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "Bad request [1]")
}

func TestCreateUser_Fail_PasswordsDontMatch(t *testing.T) {
	resetDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := loginAndGetToken(t, TestApp, superUser, superPass)

	userReq := map[string]string{
		"username":         "failuser_" + RandString(8),
		"password":         base64.StdEncoding.EncodeToString([]byte("pw1")),
		"confirm_password": base64.StdEncoding.EncodeToString([]byte("pw2")),
	}
	body, _ := json.Marshal(userReq)
	req, err := http.NewRequest("POST", "/admin/user", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "Passwords don't match")
}

func TestCreateUser_Fail_BadBase64Password(t *testing.T) {
	resetDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := loginAndGetToken(t, TestApp, superUser, superPass)

	userReq := map[string]string{
		"username":         "failuser_" + RandString(8),
		"password":         "!!notbase64!!",
		"confirm_password": "!!notbase64!!",
	}
	body, _ := json.Marshal(userReq)
	req, err := http.NewRequest("POST", "/admin/user", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "Bad base64 encoding")
}

func TestCreateUser_Fail_DBCreateError_DuplicateUsername(t *testing.T) {
	resetDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := loginAndGetToken(t, TestApp, superUser, superPass)

	// First create a user
	username := "dupuser_" + RandString(8)
	password := base64.StdEncoding.EncodeToString([]byte("pw1"))
	userReq := map[string]string{
		"username":         username,
		"password":         password,
		"confirm_password": password,
	}
	body, _ := json.Marshal(userReq)
	req, err := http.NewRequest("POST", "/admin/user", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	// Try to create the same user again to cause unique constraint violation (DB error)
	req2, err := http.NewRequest("POST", "/admin/user", bytes.NewReader(body))
	require.NoError(t, err)
	req2.Header.Set("y-access-token", token)
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w2, req2)
	require.Equal(t, http.StatusInternalServerError, w2.Code)
	require.Contains(t, w2.Body.String(), "Something went bang [1]")
}

// Note: For "DB validate error" branch (the Save after creation), this is difficult to simulate in a black-box integration test
// without complex DB-level manipulation or custom build hooks. If needed, document this coverage limitation.

func TestCreateUser_SetsAccessTokenHeader(t *testing.T) {
	resetDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := loginAndGetToken(t, TestApp, superUser, superPass)

	userReq := map[string]string{
		"username":         "headeruser_" + RandString(8),
		"password":         base64.StdEncoding.EncodeToString([]byte("pw1")),
		"confirm_password": base64.StdEncoding.EncodeToString([]byte("pw1")),
	}
	body, _ := json.Marshal(userReq)
	req, err := http.NewRequest("POST", "/admin/user", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)
	require.NotEmpty(t, w.Header().Get("y-access-token"))
}

func TestLogin_GenerateTokenError(t *testing.T) {
	resetDB(t, TestApp)
	// Save original function
	orig := utils.GenerateToken
	defer func() { utils.GenerateToken = orig }()

	// Mock GenerateToken
	utils.GenerateToken = func(username string, adminId uuid.UUID) (string, error) {
		return "", errors.New("JWT error")
	}

	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS") // Already base64 encoded!
	require.NotEmpty(t, superUser, "SUPERUSER env var must be set")
	require.NotEmpty(t, superPass, "SUPERPASS env var must be set")

	loginReq := map[string]string{
		"username": superUser,
		"password": superPass,
	}
	body, _ := json.Marshal(loginReq)
	req, err := http.NewRequest("POST", "/admin/login", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusInternalServerError, w.Code, "login ok but generate jwt fails; return 500")

	var resp map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Contains(t, resp, "message")
	require.Equal(t, "Something went bang", resp["message"])
}
