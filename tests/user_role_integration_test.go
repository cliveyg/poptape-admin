package tests

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
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

// RandString returns a random alphanumeric string of n characters, for unique test users
func RandString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[int64(len(letters))*int64(os.Getpid()+i)%int64(len(letters))]
	}
	return string(b)
}

func TestSuperuserLogin(t *testing.T) {
	testApp := setupTestApp(t)

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
	testApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, "superuser login should return 200")

	var out struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&out))
	require.NotEmpty(t, out.Token)
}

func TestUserCRUD_HappyPath(t *testing.T) {
	testApp := setupTestApp(t)

	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser, "SUPERUSER env var must be set")
	require.NotEmpty(t, superPass, "SUPERPASS env var must be set")

	token := loginAndGetToken(t, testApp, superUser, superPass)

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
	testApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "user create should return 201")

	// 2. Validate user in DB
	setUserValidated(t, testApp, userUsername)

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
	testApp.Router.ServeHTTP(w2, req2)
	require.Equal(t, http.StatusOK, w2.Code, "login as new user should return 200")
}

func TestSuperuserLogin_Fail_WrongPassword(t *testing.T) {
	testApp := setupTestApp(t)

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
	testApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code, "login with wrong password should return 401")
}

func TestUserLogin_Fail_WrongPassword(t *testing.T) {
	testApp := setupTestApp(t)

	// Setup: create and validate a user
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser, "SUPERUSER env var must be set")
	require.NotEmpty(t, superPass, "SUPERPASS env var must be set")
	token := loginAndGetToken(t, testApp, superUser, superPass)

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
	testApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "user create should return 201")

	setUserValidated(t, testApp, userUsername)

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
	testApp.Router.ServeHTTP(w2, req2)
	require.Equal(t, http.StatusUnauthorized, w2.Code, "login with wrong password should return 401")
}
