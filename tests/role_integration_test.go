package tests

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/stretchr/testify/require"
)

// --- AddRoleToUser and RemoveRoleFromUser Integration Tests ---

func TestAddRoleToUser_HappyPath(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)

	// Setup: create and validate a user (default gets "admin" role)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	superToken := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	username := "roleuser_" + testutils.RandString(8)
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
	testutils.SetUserValidated(t, TestApp, username)

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
	testutils.ResetPostgresDB(t, TestApp)
	superToken := testutils.LoginAndGetToken(t, TestApp, os.Getenv("SUPERUSER"), os.Getenv("SUPERPASS"))

	req, _ := http.NewRequest("POST", "/admin/user/notauuid/aws", nil)
	req.Header.Set("y-access-token", superToken)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "Bad request")
}

func TestAddRoleToUser_RoleDoesNotExist(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	superToken := testutils.LoginAndGetToken(t, TestApp, os.Getenv("SUPERUSER"), os.Getenv("SUPERPASS"))

	// Create user
	username := "missingroleuser_" + testutils.RandString(8)
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
	testutils.SetUserValidated(t, TestApp, username)

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
	testutils.ResetPostgresDB(t, TestApp)
	superToken := testutils.LoginAndGetToken(t, TestApp, os.Getenv("SUPERUSER"), os.Getenv("SUPERPASS"))

	username := "alreadyroleuser_" + testutils.RandString(8)
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
	testutils.SetUserValidated(t, TestApp, username)

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
	testutils.ResetPostgresDB(t, TestApp)

	// Create and validate a normal user (admin role)
	superToken := testutils.LoginAndGetToken(t, TestApp, os.Getenv("SUPERUSER"), os.Getenv("SUPERPASS"))
	username := "adminroleuser_" + testutils.RandString(8)
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
	testutils.SetUserValidated(t, TestApp, username)

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
	testutils.ResetPostgresDB(t, TestApp)

	// Setup: create and validate a user (default gets "admin" role)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	superToken := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	username := "removeuser_" + testutils.RandString(8)
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
	testutils.SetUserValidated(t, TestApp, username)

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
	testutils.ResetPostgresDB(t, TestApp)
	superToken := testutils.LoginAndGetToken(t, TestApp, os.Getenv("SUPERUSER"), os.Getenv("SUPERPASS"))

	req, _ := http.NewRequest("DELETE", "/admin/user/notauuid/admin", nil)
	req.Header.Set("y-access-token", superToken)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "Bad request")
}

func TestRemoveRoleFromUser_RoleDoesNotExist(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	superToken := testutils.LoginAndGetToken(t, TestApp, os.Getenv("SUPERUSER"), os.Getenv("SUPERPASS"))

	username := "removenoroleuser_" + testutils.RandString(8)
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
	testutils.SetUserValidated(t, TestApp, username)

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
	testutils.ResetPostgresDB(t, TestApp)
	superToken := testutils.LoginAndGetToken(t, TestApp, os.Getenv("SUPERUSER"), os.Getenv("SUPERPASS"))

	username := "notpresentuser_" + testutils.RandString(8)
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
	testutils.SetUserValidated(t, TestApp, username)

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
	testutils.ResetPostgresDB(t, TestApp)

	// Create and validate a normal user (admin role)
	superToken := testutils.LoginAndGetToken(t, TestApp, os.Getenv("SUPERUSER"), os.Getenv("SUPERPASS"))
	username := "removeadmin_" + testutils.RandString(8)
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
	testutils.SetUserValidated(t, TestApp, username)

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
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	// Create additional users
	for i := 0; i < 2; i++ {
		username := "fetchall_" + testutils.RandString(5) + fmt.Sprint(i)
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
		testutils.SetUserValidated(t, TestApp, username)
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
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	username := "fetchadmin_" + testutils.RandString(5)
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
	testutils.SetUserValidated(t, TestApp, username)

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
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	username := "nonprivuser_" + testutils.RandString(6)
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
	testutils.SetUserValidated(t, TestApp, username)

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
	testutils.ResetPostgresDB(t, TestApp)
	req, _ := http.NewRequest("GET", "/admin/users", nil)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListAllRoles_HappyPath_Superuser(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)

	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

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
	for _, r := range resp.Roles {
		require.NotEmpty(t, r.Name)
	}
}

// Admin happy path
func TestListAllRoles_HappyPath_Admin(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	superToken := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	adminUsername := "adminroles_" + testutils.RandString(6)
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
	testutils.SetUserValidated(t, TestApp, adminUsername)

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

// Forbidden for non-privileged user (e.g., aws role only)
func TestListAllRoles_Forbidden_NonPrivilegedRole(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	superToken := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	username := "awsroleuser_" + testutils.RandString(6)
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
	testutils.SetUserValidated(t, TestApp, username)
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

// Unauthorized: No token
func TestListAllRoles_Unauthorized_NoToken(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	req, _ := http.NewRequest("GET", "/admin/roles", nil)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

// No roles: Access forbidden even to superuser/admin (middleware blocks)
func TestListAllRoles_NoRoles_Forbidden(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	require.NoError(t, TestApp.DB.Exec("DELETE FROM user_role").Error)
	require.NoError(t, TestApp.DB.Exec("DELETE FROM roles").Error)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)
	req, _ := http.NewRequest("GET", "/admin/roles", nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusForbidden, w.Code)
	require.Contains(t, w.Body.String(), "Forbidden")
}
