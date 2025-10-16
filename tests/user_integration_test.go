package tests

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/cliveyg/poptape-admin/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestSuperuserLogin(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)

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
	testutils.ResetPostgresDB(t, TestApp)

	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser, "SUPERUSER env var must be set")
	require.NotEmpty(t, superPass, "SUPERPASS env var must be set")

	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	// 1. Create a new user
	userUsername := "testuser1_" + testutils.RandString(8)
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
	testutils.SetUserValidated(t, TestApp, userUsername)

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

func TestUser_NewUserLoginFailNotValidated(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)

	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser, "SUPERUSER env var must be set")
	require.NotEmpty(t, superPass, "SUPERPASS env var must be set")

	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	// 1. Create a new user
	userUsername := "testuser1_" + testutils.RandString(8)
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

	// 2. Login as new user
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
	require.Equal(t, http.StatusUnauthorized, w2.Code, "login as new user should fail as they're not validated")
	require.Contains(t, w2.Body.String(), "Username and/or password incorrect")
}

func TestSuperuserLogin_Fail_MissingFields(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)

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
	testutils.ResetPostgresDB(t, TestApp)

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
	testutils.ResetPostgresDB(t, TestApp)

	// Setup: create and validate a user
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser, "SUPERUSER env var must be set")
	require.NotEmpty(t, superPass, "SUPERPASS env var must be set")
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	userUsername := "testuser1_fail_" + testutils.RandString(8)
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

	testutils.SetUserValidated(t, TestApp, userUsername)

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
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

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
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	userReq := map[string]string{
		"username":         "failuser_" + testutils.RandString(8),
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
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	userReq := map[string]string{
		"username":         "failuser_" + testutils.RandString(8),
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
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	// First create a user
	username := "dupuser_" + testutils.RandString(8)
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
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	userReq := map[string]string{
		"username":         "headeruser_" + testutils.RandString(8),
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
	testutils.ResetPostgresDB(t, TestApp)
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

func TestLogin_ParseTokenError(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)

	orig := utils.ParseToken
	defer func() { utils.ParseToken = orig }()

	// Mock the function
	utils.ParseToken = func(ts string) (*utils.Claims, error) {
		return nil, errors.New("JWT parse token error")
	}

	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS") // Already base64 encoded!
	require.NotEmpty(t, superUser, "SUPERUSER env var must be set")
	require.NotEmpty(t, superPass, "SUPERPASS env var must be set")

	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)
	fetchReq, err := http.NewRequest("GET", "/admin/user/"+uuid.NewString(), nil)
	require.NoError(t, err)
	fetchReq.Header.Set("y-access-token", token)
	w2 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w2, fetchReq)
	require.Equal(t, http.StatusUnauthorized, w2.Code)
	require.Contains(t, w2.Body.String(), "Unauthorized")

}

// --- Tests for DeleteUser and FetchUser routes ---

func TestDeleteUser_HappyPath(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)

	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)

	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	// 1. Create user
	userUsername := "deluser_" + testutils.RandString(8)
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

	testutils.SetUserValidated(t, TestApp, userUsername)

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
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	req, err := http.NewRequest("DELETE", "/admin/user/not-a-uuid", nil)
	require.NoError(t, err)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "Bad request")
}

func TestDeleteUser_NonExistentUser(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

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
	testutils.ResetPostgresDB(t, TestApp)

	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	superToken := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	// 1. Create a normal user with admin role
	adminUsername := "adminuser_" + testutils.RandString(8)
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

	testutils.SetUserValidated(t, TestApp, adminUsername)

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
	otherUsername := "victimuser_" + testutils.RandString(8)
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

	testutils.SetUserValidated(t, TestApp, otherUsername)

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
	testutils.ResetPostgresDB(t, TestApp)

	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)

	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	userUsername := "fetchuser_" + testutils.RandString(8)
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

	testutils.SetUserValidated(t, TestApp, userUsername)

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
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	req, err := http.NewRequest("GET", "/admin/user/not-a-uuid", nil)
	require.NoError(t, err)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "Bad request")
}

func TestFetchUser_NonExistentUser(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	randomUUID := uuid.New().String()
	req, err := http.NewRequest("GET", "/admin/user/"+randomUUID, nil)
	require.NoError(t, err)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusNotFound, w.Code)
	require.Contains(t, w.Body.String(), "User not found")
}
