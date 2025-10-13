package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/cliveyg/poptape-admin/app"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// Helper: Strict UUID validation and parse
//func mustValidUUID(t *testing.T, s string) uuid.UUID {
//	require.True(t, utils.IsValidUUIDString(s), "invalid UUID string: %s", s)
//	id, err := uuid.Parse(s)
//	require.NoError(t, err)
//	return id
//}

// Helper: Login as admin, return JWT token
func loginAsAdmin(t *testing.T) string {
	loginPayload := map[string]string{
		"username": os.Getenv("SUPERUSER"),
		"password": os.Getenv("SUPERPASS"),
	}
	body, _ := json.Marshal(loginPayload)
	req := httptest.NewRequest("POST", "/admin/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	token := resp["token"]
	require.NotEmpty(t, token)
	return token
}

// Helper: Create test user, return user AdminId
func createTestUser(t *testing.T, adminToken, username string) uuid.UUID {
	payload := map[string]string{
		"username":         username,
		"password":         "cGFzc3dvcmQ=", // "password" base64
		"confirm_password": "cGFzc3dvcmQ=",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/admin/user", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	// The response does not include AdminId, so fetch from DB
	var user app.User
	res := TestApp.DB.Where("username = ?", username).First(&user)
	require.NoError(t, res.Error)
	return user.AdminId
}

// Helper: Fetch user details from API
func fetchUserDetails(t *testing.T, adminToken string, userId uuid.UUID) app.User {
	req := httptest.NewRequest("GET", fmt.Sprintf("/admin/user/%s", userId), nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		User app.User `json:"user"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	return resp.User
}

func TestUserCRUD_HappyPath(t *testing.T) {
	adminToken := loginAsAdmin(t)
	username := fmt.Sprintf("testuser_%d", time.Now().UnixNano())
	userId := createTestUser(t, adminToken, username)
	user := fetchUserDetails(t, adminToken, userId)
	require.Equal(t, username, user.Username)
}

func TestLogin_Fail_WrongPassword(t *testing.T) {
	loginPayload := map[string]string{
		"username": os.Getenv("SUPERUSER"),
		"password": "wrongpassword",
	}
	body, _ := json.Marshal(loginPayload)
	req := httptest.NewRequest("POST", "/admin/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Equal(t, "Bad request", resp["message"])
}
