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

func loginAndGetToken(t *testing.T, username, password string) string {
	loginReq := map[string]string{
		"username": username,
		"password": password,
	}
	body, _ := json.Marshal(loginReq)
	req, err := http.NewRequest("POST", "/admin/login", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, "login should return 200")

	var out struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&out))
	require.NotEmpty(t, out.Token)
	return out.Token
}

func setUserValidated(t *testing.T, username string) {
	result := TestApp.DB.Model(&app.User{}).Where("username = ?", username).Update("validated", true)
	require.NoError(t, result.Error)
}

func TestSuperuserLogin(t *testing.T) {
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser, "SUPERUSER env var must be set")
	require.NotEmpty(t, superPass, "SUPERPASS env var must be set")
	require.NotNil(t, TestApp, "TestApp must be set up by TestMain/init")

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
	superUser := "your_superuser" // or from env/config
	superPass := "your_superpass"
	require.NotNil(t, TestApp, "TestApp must be set by testapp_setup.go")

	token := loginAndGetToken(t, superUser, superPass)

	// 1. Create user
	userUsername := "testuser1"
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

	// 2. Validate user directly in DB
	setUserValidated(t, userUsername)

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

func TestLogin_Fail_WrongPassword(t *testing.T) {
	// Assume user "testuser1" exists and is validated from previous test
	loginReq := map[string]string{
		"username": "testuser1",
		"password": base64.StdEncoding.EncodeToString([]byte("wrongpass")),
	}
	body, _ := json.Marshal(loginReq)
	req, err := http.NewRequest("POST", "/admin/login", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code, "login with wrong password should return 401")
}
