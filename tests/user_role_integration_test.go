package tests

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/stretchr/testify/require"
)

// Helper: login as the given user and return JWT token string
func loginAndGetToken(t *testing.T, serverURL, username, password string) string {
	loginReq := map[string]string{
		"username": username,
		"password": base64.StdEncoding.EncodeToString([]byte(password)),
	}
	body, _ := json.Marshal(loginReq)
	req, err := http.NewRequest("POST", serverURL+"/admin/login", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "login should return 200")

	var out struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	require.NotEmpty(t, out.Token)
	return out.Token
}

// Helper: set Validated=true for a user in the DB using TestApp.DB
func setUserValidated(t *testing.T, username string) {
	result := TestApp.DB.Model(&app.User{}).Where("username = ?", username).Update("validated", true)
	require.NoError(t, result.Error)
}

func TestUserCRUD_HappyPath(t *testing.T) {
	serverURL := os.Getenv("API_URL")
	if serverURL == "" {
		serverURL = "http://localhost:8080"
	}

	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser, "SUPERUSER env var must be set")
	require.NotEmpty(t, superPass, "SUPERPASS env var must be set")
	require.NotNil(t, TestApp, "TestApp must be set up by TestMain/init")

	token := loginAndGetToken(t, serverURL, superUser, superPass)

	// 1. Create a new user using /admin/user (requires y-access-token)
	userUsername := "testuser1"
	userPassword := "testpass1"
	userReq := map[string]string{
		"username":         userUsername,
		"password":         base64.StdEncoding.EncodeToString([]byte(userPassword)),
		"confirm_password": base64.StdEncoding.EncodeToString([]byte(userPassword)),
	}
	body, _ := json.Marshal(userReq)
	req, err := http.NewRequest("POST", serverURL+"/admin/user", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode, "user create should return 201")

	// 2. Set Validated=true in the DB for the new user
	setUserValidated(t, userUsername)

	// 3. Login as the new user
	loginReq := map[string]string{
		"username": userUsername,
		"password": base64.StdEncoding.EncodeToString([]byte(userPassword)),
	}
	body, _ = json.Marshal(loginReq)
	req2, err := http.NewRequest("POST", serverURL+"/admin/login", bytes.NewReader(body))
	require.NoError(t, err)
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err)
	defer resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode, "login as new user should return 200")
}

func TestLogin_Fail_WrongPassword(t *testing.T) {
	serverURL := os.Getenv("API_URL")
	if serverURL == "" {
		serverURL = "http://localhost:8080"
	}
	// Assume user "testuser1" exists and is validated from previous test
	loginReq := map[string]string{
		"username": "testuser1",
		"password": base64.StdEncoding.EncodeToString([]byte("wrongpass")),
	}
	body, _ := json.Marshal(loginReq)
	req, err := http.NewRequest("POST", serverURL+"/admin/login", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "login with wrong password should return 401")
}
