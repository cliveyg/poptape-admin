package tests

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// Helper: login as superuser and return token
func loginAndGetToken(t *testing.T, serverURL, superUser, superPass string) string {
	loginReq := map[string]string{
		"username": superUser,
		"password": base64.StdEncoding.EncodeToString([]byte(superPass)),
	}
	body, _ := json.Marshal(loginReq)
	resp, err := http.Post(serverURL+"/admin/login", "application/json", bytes.NewReader(body))
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

func TestUserCRUD_HappyPath(t *testing.T) {
	serverURL := os.Getenv("API_URL") // or use testutils/server as appropriate
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")

	token := loginAndGetToken(t, serverURL, superUser, superPass)

	userReq := map[string]string{
		"username":         "testuser1",
		"password":         base64.StdEncoding.EncodeToString([]byte("testpass1")),
		"confirm_password": base64.StdEncoding.EncodeToString([]byte("testpass1")),
	}
	body, _ := json.Marshal(userReq)
	req, _ := http.NewRequest("POST", serverURL+"/admin/user", bytes.NewReader(body))
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode, "user create should return 201")

	// Optionally parse response for created user info

	// 2. Login as new user
	loginReq := map[string]string{
		"username": "testuser1",
		"password": base64.StdEncoding.EncodeToString([]byte("testpass1")),
	}
	body, _ = json.Marshal(loginReq)
	resp2, err := http.Post(serverURL+"/admin/login", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode, "login as new user should return 200")
}

func TestLogin_Fail_WrongPassword(t *testing.T) {
	serverURL := os.Getenv("API_URL")
	// Assume user "testuser1" exists from previous test
	loginReq := map[string]string{
		"username": "testuser1",
		"password": base64.StdEncoding.EncodeToString([]byte("wrongpass")),
	}
	body, _ := json.Marshal(loginReq)
	resp, err := http.Post(serverURL+"/admin/login", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "login with wrong password should return 401")
}
