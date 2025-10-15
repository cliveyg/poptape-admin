package tests

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cliveyg/poptape-admin/utils"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/stretchr/testify/require"
)

func getFirstRoleName(t *testing.T) string {
	var role app.Role
	err := TestApp.DB.Order("name asc").First(&role).Error
	require.NoError(t, err)
	return role.Name
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
	// save original function
	orig := utils.GenerateToken
	defer func() { utils.GenerateToken = orig }()

	// mock GenerateToken
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

// --- Tests for DeleteUser and FetchUser routes ---

func TestDeleteUser_HappyPath(t *testing.T) {
	resetDB(t, TestApp)

	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)

	token := loginAndGetToken(t, TestApp, superUser, superPass)

	// 1. Create user
	userUsername := "deluser_" + RandString(8)
	userPassword := "delpass1"
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
	require.Equal(t, http.StatusCreated, w.Code)

	setUserValidated(t, TestApp, userUsername)

	var user app.User
	err = TestApp.DB.Where("username = ?", userUsername).First(&user).Error
	require.NoError(t, err)
	require.NotEqual(t, uuid.Nil, user.AdminId)

	delReq, err := http.NewRequest("DELETE", "/admin/user/"+user.AdminId.String(), nil)
	require.NoError(t, err)
	delReq.Header.Set("y-access-token", token)
	w2 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w2, delReq)
	require.Equal(t, http.StatusGone, w2.Code)
	require.Contains(t, w2.Body.String(), "User deleted")

	// Confirm user is deleted (fetch should 404)
	fetchReq, err := http.NewRequest("GET", "/admin/user/"+user.AdminId.String(), nil)
	require.NoError(t, err)
	fetchReq.Header.Set("y-access-token", token)
	w3 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w3, fetchReq)
	require.Equal(t, http.StatusNotFound, w3.Code)
}

func TestDeleteUser_BadUUID(t *testing.T) {
	resetDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := loginAndGetToken(t, TestApp, superUser, superPass)

	req, err := http.NewRequest("DELETE", "/admin/user/not-a-uuid", nil)
	require.NoError(t, err)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "Bad request")
}

func TestDeleteUser_NonExistentUser(t *testing.T) {
	resetDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := loginAndGetToken(t, TestApp, superUser, superPass)

	randomUUID := uuid.New().String()
	req, err := http.NewRequest("DELETE", "/admin/user/"+randomUUID, nil)
	require.NoError(t, err)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusGone, w.Code)
	require.Contains(t, w.Body.String(), "User deleted")
}

func TestDeleteUser_AdminCannotDeleteUser(t *testing.T) {
	resetDB(t, TestApp)

	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	superToken := loginAndGetToken(t, TestApp, superUser, superPass)

	// 1. Create a normal user with admin role
	adminUsername := "adminuser_" + RandString(8)
	adminPassword := "adminpass"
	adminReq := map[string]string{
		"username":         adminUsername,
		"password":         base64.StdEncoding.EncodeToString([]byte(adminPassword)),
		"confirm_password": base64.StdEncoding.EncodeToString([]byte(adminPassword)),
	}
	body, _ := json.Marshal(adminReq)
	req, err := http.NewRequest("POST", "/admin/user", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("y-access-token", superToken)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	setUserValidated(t, TestApp, adminUsername)

	// 2. Login as admin user (match how other tests do user logins)
	loginReq := map[string]string{
		"username": adminUsername,
		"password": base64.StdEncoding.EncodeToString([]byte(adminPassword)),
	}
	body, _ = json.Marshal(loginReq)
	reqLogin, err := http.NewRequest("POST", "/admin/login", bytes.NewReader(body))
	require.NoError(t, err)
	reqLogin.Header.Set("Content-Type", "application/json")
	wLogin := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(wLogin, reqLogin)
	require.Equal(t, http.StatusOK, wLogin.Code, "login should return 200")

	var out struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.NewDecoder(wLogin.Body).Decode(&out))
	require.NotEmpty(t, out.Token)
	adminToken := out.Token

	// 3. Create another normal user to be deleted
	otherUsername := "victimuser_" + RandString(8)
	otherPassword := "victimpass"
	otherReq := map[string]string{
		"username":         otherUsername,
		"password":         base64.StdEncoding.EncodeToString([]byte(otherPassword)),
		"confirm_password": base64.StdEncoding.EncodeToString([]byte(otherPassword)),
	}
	body, _ = json.Marshal(otherReq)
	req2, err := http.NewRequest("POST", "/admin/user", bytes.NewReader(body))
	require.NoError(t, err)
	req2.Header.Set("y-access-token", superToken)
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w2, req2)
	require.Equal(t, http.StatusCreated, w2.Code)

	setUserValidated(t, TestApp, otherUsername)

	var victimUser app.User
	err = TestApp.DB.Where("username = ?", otherUsername).First(&victimUser).Error
	require.NoError(t, err)
	require.NotEqual(t, uuid.Nil, victimUser.AdminId)

	// 4. Try to delete victim as admin (should fail - forbidden)
	delReq, err := http.NewRequest("DELETE", "/admin/user/"+victimUser.AdminId.String(), nil)
	require.NoError(t, err)
	delReq.Header.Set("y-access-token", adminToken)
	w3 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w3, delReq)
	require.Equal(t, http.StatusForbidden, w3.Code)
	require.Contains(t, w3.Body.String(), "Forbidden")
}

func TestFetchUser_HappyPath(t *testing.T) {
	resetDB(t, TestApp)

	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)

	token := loginAndGetToken(t, TestApp, superUser, superPass)

	userUsername := "fetchuser_" + RandString(8)
	userPassword := "fetchpass1"
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
	require.Equal(t, http.StatusCreated, w.Code)

	setUserValidated(t, TestApp, userUsername)

	var user app.User
	err = TestApp.DB.Where("username = ?", userUsername).First(&user).Error
	require.NoError(t, err)
	require.NotEqual(t, uuid.Nil, user.AdminId)

	fetchReq, err := http.NewRequest("GET", "/admin/user/"+user.AdminId.String(), nil)
	require.NoError(t, err)
	fetchReq.Header.Set("y-access-token", token)
	w2 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w2, fetchReq)
	require.Equal(t, http.StatusOK, w2.Code)
	require.Contains(t, w2.Body.String(), userUsername)
}

func TestFetchUser_BadUUID(t *testing.T) {
	resetDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := loginAndGetToken(t, TestApp, superUser, superPass)

	req, err := http.NewRequest("GET", "/admin/user/not-a-uuid", nil)
	require.NoError(t, err)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "Bad request")
}

func TestFetchUser_NonExistentUser(t *testing.T) {
	resetDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := loginAndGetToken(t, TestApp, superUser, superPass)

	randomUUID := uuid.New().String()
	req, err := http.NewRequest("GET", "/admin/user/"+randomUUID, nil)
	require.NoError(t, err)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusNotFound, w.Code)
	require.Contains(t, w.Body.String(), "User not found")
}

// --- AddRoleToUser and RemoveRoleFromUser Integration Tests ---

func TestAddRoleToUser_HappyPath(t *testing.T) {
	resetDB(t, TestApp)

	// Setup: create and validate a user (default gets "admin" role)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	superToken := loginAndGetToken(t, TestApp, superUser, superPass)

	username := "roleuser_" + RandString(8)
	password := "rolepass"
	userReq := map[string]string{
		"username":         username,
		"password":         base64.StdEncoding.EncodeToString([]byte(password)),
		"confirm_password": base64.StdEncoding.EncodeToString([]byte(password)),
	}
	body, _ := json.Marshal(userReq)
	reqUser, _ := http.NewRequest("POST", "/admin/user", bytes.NewReader(body))
	reqUser.Header.Set("y-access-token", superToken)
	reqUser.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, reqUser)
	require.Equal(t, http.StatusCreated, w.Code)
	setUserValidated(t, TestApp, username)

	var user app.User
	err := TestApp.DB.Where("username = ?", username).First(&user).Error
	require.NoError(t, err)
	require.NotEqual(t, uuid.Nil, user.AdminId)

	// Add a new role ("aws" is a seeded role)
	addRoleReq, _ := http.NewRequest("POST", "/admin/user/"+user.AdminId.String()+"/aws", nil)
	addRoleReq.Header.Set("y-access-token", superToken)
	w2 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w2, addRoleReq)
	require.Equal(t, http.StatusCreated, w2.Code)
	require.Contains(t, w2.Body.String(), "Role [aws] added to user")
}

func TestAddRoleToUser_BadUUID(t *testing.T) {
	resetDB(t, TestApp)
	superToken := loginAndGetToken(t, TestApp, os.Getenv("SUPERUSER"), os.Getenv("SUPERPASS"))

	req, _ := http.NewRequest("POST", "/admin/user/notauuid/aws", nil)
	req.Header.Set("y-access-token", superToken)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "Bad request")
}

func TestAddRoleToUser_RoleDoesNotExist(t *testing.T) {
	resetDB(t, TestApp)
	superToken := loginAndGetToken(t, TestApp, os.Getenv("SUPERUSER"), os.Getenv("SUPERPASS"))

	// Create user
	username := "missingroleuser_" + RandString(8)
	password := "pass"
	userReq := map[string]string{
		"username":         username,
		"password":         base64.StdEncoding.EncodeToString([]byte(password)),
		"confirm_password": base64.StdEncoding.EncodeToString([]byte(password)),
	}
	body, _ := json.Marshal(userReq)
	reqUser, _ := http.NewRequest("POST", "/admin/user", bytes.NewReader(body))
	reqUser.Header.Set("y-access-token", superToken)
	reqUser.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, reqUser)
	require.Equal(t, http.StatusCreated, w.Code)
	setUserValidated(t, TestApp, username)

	var user app.User
	_ = TestApp.DB.Where("username = ?", username).First(&user).Error

	// Try to add a truly non-existent role
	req2, _ := http.NewRequest("POST", "/admin/user/"+user.AdminId.String()+"/definitelynotarole", nil)
	req2.Header.Set("y-access-token", superToken)
	w2 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w2, req2)
	require.Equal(t, http.StatusNotFound, w2.Code)
	require.Contains(t, w2.Body.String(), "Role does not exist")
}

func TestAddRoleToUser_RoleAlreadyPresent(t *testing.T) {
	resetDB(t, TestApp)
	superToken := loginAndGetToken(t, TestApp, os.Getenv("SUPERUSER"), os.Getenv("SUPERPASS"))

	username := "alreadyroleuser_" + RandString(8)
	password := "pass"
	userReq := map[string]string{
		"username":         username,
		"password":         base64.StdEncoding.EncodeToString([]byte(password)),
		"confirm_password": base64.StdEncoding.EncodeToString([]byte(password)),
	}
	body, _ := json.Marshal(userReq)
	reqUser, _ := http.NewRequest("POST", "/admin/user", bytes.NewReader(body))
	reqUser.Header.Set("y-access-token", superToken)
	reqUser.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, reqUser)
	require.Equal(t, http.StatusCreated, w.Code)
	setUserValidated(t, TestApp, username)

	var user app.User
	_ = TestApp.DB.Where("username = ?", username).First(&user).Error

	// Try to add the default "admin" role again
	req2, _ := http.NewRequest("POST", "/admin/user/"+user.AdminId.String()+"/admin", nil)
	req2.Header.Set("y-access-token", superToken)
	w2 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w2, req2)
	require.Equal(t, http.StatusNotModified, w2.Code)
	// Do not check body, as 304 may have empty body
}

func TestAddRoleToUser_ForbiddenIfNotSuper(t *testing.T) {
	resetDB(t, TestApp)

	// Create and validate a normal user (admin role)
	superToken := loginAndGetToken(t, TestApp, os.Getenv("SUPERUSER"), os.Getenv("SUPERPASS"))
	username := "adminroleuser_" + RandString(8)
	password := "pass"
	userReq := map[string]string{
		"username":         username,
		"password":         base64.StdEncoding.EncodeToString([]byte(password)),
		"confirm_password": base64.StdEncoding.EncodeToString([]byte(password)),
	}
	body, _ := json.Marshal(userReq)
	reqUser, _ := http.NewRequest("POST", "/admin/user", bytes.NewReader(body))
	reqUser.Header.Set("y-access-token", superToken)
	reqUser.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, reqUser)
	require.Equal(t, http.StatusCreated, w.Code)
	setUserValidated(t, TestApp, username)

	// Login as the admin-role user
	loginReq := map[string]string{
		"username": username,
		"password": base64.StdEncoding.EncodeToString([]byte(password)),
	}
	body, _ = json.Marshal(loginReq)
	reqLogin, _ := http.NewRequest("POST", "/admin/login", bytes.NewReader(body))
	reqLogin.Header.Set("Content-Type", "application/json")
	wLogin := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(wLogin, reqLogin)
	require.Equal(t, http.StatusOK, wLogin.Code)
	var out struct{ Token string }
	require.NoError(t, json.NewDecoder(wLogin.Body).Decode(&out))
	adminToken := out.Token

	// Try to add a role as the admin user (should be forbidden)
	var user app.User
	_ = TestApp.DB.Where("username = ?", username).First(&user).Error
	req2, _ := http.NewRequest("POST", "/admin/user/"+user.AdminId.String()+"/aws", nil)
	req2.Header.Set("y-access-token", adminToken)
	w2 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w2, req2)
	require.Equal(t, http.StatusForbidden, w2.Code)
	require.Contains(t, w2.Body.String(), "Forbidden")
}

// --- RemoveRoleFromUser tests ---

func TestRemoveRoleFromUser_HappyPath(t *testing.T) {
	resetDB(t, TestApp)

	// Setup: create and validate a user (default gets "admin" role)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	superToken := loginAndGetToken(t, TestApp, superUser, superPass)

	username := "removeuser_" + RandString(8)
	password := "removeuserpass"
	userReq := map[string]string{
		"username":         username,
		"password":         base64.StdEncoding.EncodeToString([]byte(password)),
		"confirm_password": base64.StdEncoding.EncodeToString([]byte(password)),
	}
	body, _ := json.Marshal(userReq)
	reqUser, _ := http.NewRequest("POST", "/admin/user", bytes.NewReader(body))
	reqUser.Header.Set("y-access-token", superToken)
	reqUser.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, reqUser)
	require.Equal(t, http.StatusCreated, w.Code)
	setUserValidated(t, TestApp, username)

	var user app.User
	err := TestApp.DB.Where("username = ?", username).First(&user).Error
	require.NoError(t, err)
	require.NotEqual(t, uuid.Nil, user.AdminId)

	// Remove the "admin" role
	removeRoleReq, _ := http.NewRequest("DELETE", "/admin/user/"+user.AdminId.String()+"/admin", nil)
	removeRoleReq.Header.Set("y-access-token", superToken)
	w2 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w2, removeRoleReq)
	require.Equal(t, http.StatusGone, w2.Code)
	require.Contains(t, w2.Body.String(), "Role [admin] removed from user")
}

func TestRemoveRoleFromUser_BadUUID(t *testing.T) {
	resetDB(t, TestApp)
	superToken := loginAndGetToken(t, TestApp, os.Getenv("SUPERUSER"), os.Getenv("SUPERPASS"))

	req, _ := http.NewRequest("DELETE", "/admin/user/notauuid/admin", nil)
	req.Header.Set("y-access-token", superToken)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "Bad request")
}

func TestRemoveRoleFromUser_RoleDoesNotExist(t *testing.T) {
	resetDB(t, TestApp)
	superToken := loginAndGetToken(t, TestApp, os.Getenv("SUPERUSER"), os.Getenv("SUPERPASS"))

	username := "removenoroleuser_" + RandString(8)
	password := "pass"
	userReq := map[string]string{
		"username":         username,
		"password":         base64.StdEncoding.EncodeToString([]byte(password)),
		"confirm_password": base64.StdEncoding.EncodeToString([]byte(password)),
	}
	body, _ := json.Marshal(userReq)
	reqUser, _ := http.NewRequest("POST", "/admin/user", bytes.NewReader(body))
	reqUser.Header.Set("y-access-token", superToken)
	reqUser.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, reqUser)
	require.Equal(t, http.StatusCreated, w.Code)
	setUserValidated(t, TestApp, username)

	var user app.User
	_ = TestApp.DB.Where("username = ?", username).First(&user).Error

	// Use a role that is not in the seeded list, is <=20 chars, and matches ^[a-z_]+$
	roleName := "foobar"
	var role app.Role
	err := TestApp.DB.Where("name = ?", roleName).First(&role).Error
	require.Error(t, err, "Role should not exist in DB")

	req2, _ := http.NewRequest("DELETE", "/admin/user/"+user.AdminId.String()+"/"+roleName, nil)
	req2.Header.Set("y-access-token", superToken)
	w2 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w2, req2)
	require.Equal(t, http.StatusNotModified, w2.Code, "Should return 304 if user does not have the role (regardless of role existence)")
	// Optionally, check message, but body may be empty for 304:
	// require.Contains(t, w2.Body.String(), "Incorrect input")
}

func TestRemoveRoleFromUser_RoleNotPresentOnUser(t *testing.T) {
	resetDB(t, TestApp)
	superToken := loginAndGetToken(t, TestApp, os.Getenv("SUPERUSER"), os.Getenv("SUPERPASS"))

	username := "notpresentuser_" + RandString(8)
	password := "pass"
	userReq := map[string]string{
		"username":         username,
		"password":         base64.StdEncoding.EncodeToString([]byte(password)),
		"confirm_password": base64.StdEncoding.EncodeToString([]byte(password)),
	}
	body, _ := json.Marshal(userReq)
	reqUser, _ := http.NewRequest("POST", "/admin/user", bytes.NewReader(body))
	reqUser.Header.Set("y-access-token", superToken)
	reqUser.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, reqUser)
	require.Equal(t, http.StatusCreated, w.Code)
	setUserValidated(t, TestApp, username)

	var user app.User
	_ = TestApp.DB.Where("username = ?", username).First(&user).Error

	// Try to remove the "aws" role, which user does NOT have
	req2, _ := http.NewRequest("DELETE", "/admin/user/"+user.AdminId.String()+"/aws", nil)
	req2.Header.Set("y-access-token", superToken)
	w2 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w2, req2)
	require.Equal(t, http.StatusNotModified, w2.Code)
	// Do not check body, as 304 may be empty
}

func TestRemoveRoleFromUser_ForbiddenIfNotSuper(t *testing.T) {
	resetDB(t, TestApp)

	// Create and validate a normal user (admin role)
	superToken := loginAndGetToken(t, TestApp, os.Getenv("SUPERUSER"), os.Getenv("SUPERPASS"))
	username := "removeadmin_" + RandString(8)
	password := "pass"
	userReq := map[string]string{
		"username":         username,
		"password":         base64.StdEncoding.EncodeToString([]byte(password)),
		"confirm_password": base64.StdEncoding.EncodeToString([]byte(password)),
	}
	body, _ := json.Marshal(userReq)
	reqUser, _ := http.NewRequest("POST", "/admin/user", bytes.NewReader(body))
	reqUser.Header.Set("y-access-token", superToken)
	reqUser.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, reqUser)
	require.Equal(t, http.StatusCreated, w.Code)
	setUserValidated(t, TestApp, username)

	// Login as the admin-role user
	loginReq := map[string]string{
		"username": username,
		"password": base64.StdEncoding.EncodeToString([]byte(password)),
	}
	body, _ = json.Marshal(loginReq)
	reqLogin, _ := http.NewRequest("POST", "/admin/login", bytes.NewReader(body))
	reqLogin.Header.Set("Content-Type", "application/json")
	wLogin := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(wLogin, reqLogin)
	require.Equal(t, http.StatusOK, wLogin.Code)
	var out struct{ Token string }
	require.NoError(t, json.NewDecoder(wLogin.Body).Decode(&out))
	adminToken := out.Token

	var user app.User
	_ = TestApp.DB.Where("username = ?", username).First(&user).Error
	req2, _ := http.NewRequest("DELETE", "/admin/user/"+user.AdminId.String()+"/admin", nil)
	req2.Header.Set("y-access-token", adminToken)
	w2 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w2, req2)
	require.Equal(t, http.StatusForbidden, w2.Code)
	require.Contains(t, w2.Body.String(), "Forbidden")
}

func TestFetchAllUsers_HappyPath_Super(t *testing.T) {
	resetDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := loginAndGetToken(t, TestApp, superUser, superPass)

	// Create additional users
	for i := 0; i < 2; i++ {
		username := "fetchall_" + RandString(5) + fmt.Sprint(i)
		password := "pw"
		userReq := map[string]string{
			"username":         username,
			"password":         base64.StdEncoding.EncodeToString([]byte(password)),
			"confirm_password": base64.StdEncoding.EncodeToString([]byte(password)),
		}
		body, _ := json.Marshal(userReq)
		req, _ := http.NewRequest("POST", "/admin/user", bytes.NewReader(body))
		req.Header.Set("y-access-token", token)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		TestApp.Router.ServeHTTP(w, req)
		require.Equal(t, http.StatusCreated, w.Code)
		setUserValidated(t, TestApp, username)
	}

	req, _ := http.NewRequest("GET", "/admin/users", nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Users []app.User `json:"users"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	require.GreaterOrEqual(t, len(resp.Users), 3)
}

func TestFetchAllUsers_HappyPath_Admin(t *testing.T) {
	resetDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	token := loginAndGetToken(t, TestApp, superUser, superPass)

	username := "fetchadmin_" + RandString(5)
	password := "pw"
	userReq := map[string]string{
		"username":         username,
		"password":         base64.StdEncoding.EncodeToString([]byte(password)),
		"confirm_password": base64.StdEncoding.EncodeToString([]byte(password)),
	}
	body, _ := json.Marshal(userReq)
	req, _ := http.NewRequest("POST", "/admin/user", bytes.NewReader(body))
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)
	setUserValidated(t, TestApp, username)

	// Login as admin user
	loginReq := map[string]string{
		"username": username,
		"password": base64.StdEncoding.EncodeToString([]byte(password)),
	}
	body, _ = json.Marshal(loginReq)
	reqLogin, _ := http.NewRequest("POST", "/admin/login", bytes.NewReader(body))
	reqLogin.Header.Set("Content-Type", "application/json")
	wLogin := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(wLogin, reqLogin)
	require.Equal(t, http.StatusOK, wLogin.Code)
	var out struct{ Token string }
	require.NoError(t, json.NewDecoder(wLogin.Body).Decode(&out))
	adminToken := out.Token

	req2, _ := http.NewRequest("GET", "/admin/users", nil)
	req2.Header.Set("y-access-token", adminToken)
	w2 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w2, req2)
	require.Equal(t, http.StatusOK, w2.Code)
	var resp struct {
		Users []app.User `json:"users"`
	}
	require.NoError(t, json.NewDecoder(w2.Body).Decode(&resp))
	require.GreaterOrEqual(t, len(resp.Users), 2)
}

func TestFetchAllUsers_Forbidden_OtherRole(t *testing.T) {
	resetDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	token := loginAndGetToken(t, TestApp, superUser, superPass)

	username := "nonprivuser_" + RandString(6)
	password := "pw"
	userReq := map[string]string{
		"username":         username,
		"password":         base64.StdEncoding.EncodeToString([]byte(password)),
		"confirm_password": base64.StdEncoding.EncodeToString([]byte(password)),
	}
	body, _ := json.Marshal(userReq)
	req, _ := http.NewRequest("POST", "/admin/user", bytes.NewReader(body))
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)
	setUserValidated(t, TestApp, username)

	// Add "aws" role
	var user app.User
	require.NoError(t, TestApp.DB.Where("username = ?", username).First(&user).Error)
	addRoleReq, _ := http.NewRequest("POST", "/admin/user/"+user.AdminId.String()+"/aws", nil)
	addRoleReq.Header.Set("y-access-token", token)
	w2 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w2, addRoleReq)
	require.Equal(t, http.StatusCreated, w2.Code)

	// Remove "admin" role
	removeRoleReq, _ := http.NewRequest("DELETE", "/admin/user/"+user.AdminId.String()+"/admin", nil)
	removeRoleReq.Header.Set("y-access-token", token)
	w3 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w3, removeRoleReq)
	require.Equal(t, http.StatusGone, w3.Code)

	// Login as user (now only "aws" role)
	loginReq := map[string]string{
		"username": username,
		"password": base64.StdEncoding.EncodeToString([]byte(password)),
	}
	body, _ = json.Marshal(loginReq)
	reqLogin, _ := http.NewRequest("POST", "/admin/login", bytes.NewReader(body))
	reqLogin.Header.Set("Content-Type", "application/json")
	wLogin := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(wLogin, reqLogin)
	require.Equal(t, http.StatusOK, wLogin.Code)
	var out struct{ Token string }
	require.NoError(t, json.NewDecoder(wLogin.Body).Decode(&out))
	awsToken := out.Token

	req2, _ := http.NewRequest("GET", "/admin/users", nil)
	req2.Header.Set("y-access-token", awsToken)
	w2 = httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w2, req2)
	require.Equal(t, http.StatusForbidden, w2.Code)
	require.Contains(t, w2.Body.String(), "Forbidden")
}

func TestFetchAllUsers_Unauthorized_NoToken(t *testing.T) {
	resetDB(t, TestApp)
	req, _ := http.NewRequest("GET", "/admin/users", nil)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListAllRoles_HappyPath_Superuser(t *testing.T) {
	resetDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)

	token := loginAndGetToken(t, TestApp, superUser, superPass)

	req, err := http.NewRequest("GET", "/admin/roles", nil)
	require.NoError(t, err)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Roles []app.Role `json:"roles"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	require.NotEmpty(t, resp.Roles)
	// All roles returned should have non-empty Name fields
	for _, r := range resp.Roles {
		require.NotEmpty(t, r.Name)
	}
}

func TestListAllRoles_HappyPath_Admin(t *testing.T) {
	resetDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	superToken := loginAndGetToken(t, TestApp, superUser, superPass)

	adminUsername := "adminroles_" + RandString(6)
	adminPassword := "pw"
	userReq := map[string]string{
		"username":         adminUsername,
		"password":         base64.StdEncoding.EncodeToString([]byte(adminPassword)),
		"confirm_password": base64.StdEncoding.EncodeToString([]byte(adminPassword)),
	}
	body, _ := json.Marshal(userReq)
	req, _ := http.NewRequest("POST", "/admin/user", bytes.NewReader(body))
	req.Header.Set("y-access-token", superToken)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)
	setUserValidated(t, TestApp, adminUsername)

	loginReq := map[string]string{
		"username": adminUsername,
		"password": base64.StdEncoding.EncodeToString([]byte(adminPassword)),
	}
	body, _ = json.Marshal(loginReq)
	req2, _ := http.NewRequest("POST", "/admin/login", bytes.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w2, req2)
	require.Equal(t, http.StatusOK, w2.Code)
	var out struct{ Token string }
	require.NoError(t, json.NewDecoder(w2.Body).Decode(&out))
	adminToken := out.Token

	req3, _ := http.NewRequest("GET", "/admin/roles", nil)
	req3.Header.Set("y-access-token", adminToken)
	w3 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w3, req3)
	require.Equal(t, http.StatusOK, w3.Code)
	var resp struct {
		Roles []app.Role `json:"roles"`
	}
	require.NoError(t, json.NewDecoder(w3.Body).Decode(&resp))
	require.NotEmpty(t, resp.Roles)
	for _, r := range resp.Roles {
		require.NotEmpty(t, r.Name)
	}
}

func TestListAllRoles_Forbidden_NonPrivilegedRole(t *testing.T) {
	resetDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	superToken := loginAndGetToken(t, TestApp, superUser, superPass)

	username := "awsroleuser_" + RandString(6)
	password := "pw"
	userReq := map[string]string{
		"username":         username,
		"password":         base64.StdEncoding.EncodeToString([]byte(password)),
		"confirm_password": base64.StdEncoding.EncodeToString([]byte(password)),
	}
	body, _ := json.Marshal(userReq)
	req, _ := http.NewRequest("POST", "/admin/user", bytes.NewReader(body))
	req.Header.Set("y-access-token", superToken)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)
	setUserValidated(t, TestApp, username)
	var user app.User
	require.NoError(t, TestApp.DB.Where("username = ?", username).First(&user).Error)
	// Add "aws" role, remove "admin" role
	addRoleReq, _ := http.NewRequest("POST", "/admin/user/"+user.AdminId.String()+"/aws", nil)
	addRoleReq.Header.Set("y-access-token", superToken)
	w2 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w2, addRoleReq)
	require.Equal(t, http.StatusCreated, w2.Code)
	removeRoleReq, _ := http.NewRequest("DELETE", "/admin/user/"+user.AdminId.String()+"/admin", nil)
	removeRoleReq.Header.Set("y-access-token", superToken)
	w3 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w3, removeRoleReq)
	require.Equal(t, http.StatusGone, w3.Code)
	// Login as aws-only user
	loginReq := map[string]string{
		"username": username,
		"password": base64.StdEncoding.EncodeToString([]byte(password)),
	}
	body, _ = json.Marshal(loginReq)
	reqLogin, _ := http.NewRequest("POST", "/admin/login", bytes.NewReader(body))
	reqLogin.Header.Set("Content-Type", "application/json")
	wLogin := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(wLogin, reqLogin)
	require.Equal(t, http.StatusOK, wLogin.Code)
	var out struct{ Token string }
	require.NoError(t, json.NewDecoder(wLogin.Body).Decode(&out))
	awsToken := out.Token

	req4, _ := http.NewRequest("GET", "/admin/roles", nil)
	req4.Header.Set("y-access-token", awsToken)
	w4 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w4, req4)
	require.Equal(t, http.StatusForbidden, w4.Code)
	require.Contains(t, w4.Body.String(), "Forbidden")
}

func TestListAllRoles_Unauthorized_NoToken(t *testing.T) {
	resetDB(t, TestApp)
	req, _ := http.NewRequest("GET", "/admin/roles", nil)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListAllRoles_InternalServerError_WhenNoRoles(t *testing.T) {
	resetDB(t, TestApp)
	// Remove all roles
	require.NoError(t, TestApp.DB.Exec("DELETE FROM roles").Error)
	// Use superuser
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	token := loginAndGetToken(t, TestApp, superUser, superPass)
	req, _ := http.NewRequest("GET", "/admin/roles", nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusInternalServerError, w.Code)
	require.Contains(t, w.Body.String(), "Something went neee")
}
