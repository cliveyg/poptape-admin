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

// Helper to construct a valid creds payload
func validCredsPayload() map[string]interface{} {
	return map[string]interface{}{
		"db_name":     "poptape_items",
		"type":        "mongo",
		"url":         "/items",
		"db_username": "poptape_items",
		"db_password": "cGFzc3dvcmQ=",
		"db_port":     "27017",
		"host":        "poptape-items-mongodb-1",
		"role_name":   "items",
		"ms_name":     "items",
	}
}

func TestCreateCreds_HappyPath_Super(t *testing.T) {
	resetDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := loginAndGetToken(t, TestApp, superUser, superPass)

	payload := validCredsPayload()
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", "/admin/creds", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)

	require.Equal(t, http.StatusCreated, w.Code)
	require.Contains(t, w.Body.String(), "Creds created; credId is [")
}

func TestCreateCreds_HappyPath_Admin(t *testing.T) {
	resetDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	superToken := loginAndGetToken(t, TestApp, superUser, superPass)

	// Create & validate an admin user
	adminUsername := "admincreds_" + RandString(6)
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

	// Login as admin user
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

	creds := validCredsPayload()
	body, _ = json.Marshal(creds)
	req3, _ := http.NewRequest("POST", "/admin/creds", bytes.NewReader(body))
	req3.Header.Set("y-access-token", adminToken)
	req3.Header.Set("Content-Type", "application/json")
	w3 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w3, req3)
	require.Equal(t, http.StatusCreated, w3.Code)
	require.Contains(t, w3.Body.String(), "Creds created; credId is [")
}

func TestCreateCreds_Forbidden_NonPrivilegedRole(t *testing.T) {
	resetDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	superToken := loginAndGetToken(t, TestApp, superUser, superPass)

	username := "awscreds_" + RandString(6)
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

	creds := validCredsPayload()
	body, _ = json.Marshal(creds)
	req4, _ := http.NewRequest("POST", "/admin/creds", bytes.NewReader(body))
	req4.Header.Set("y-access-token", awsToken)
	req4.Header.Set("Content-Type", "application/json")
	w4 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w4, req4)
	require.Equal(t, http.StatusForbidden, w4.Code)
	require.Contains(t, w4.Body.String(), "Forbidden")
}

func TestCreateCreds_Unauthorized_NoToken(t *testing.T) {
	resetDB(t, TestApp)
	creds := validCredsPayload()
	body, _ := json.Marshal(creds)
	req, _ := http.NewRequest("POST", "/admin/creds", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCreateCreds_Fail_InvalidDBType(t *testing.T) {
	resetDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := loginAndGetToken(t, TestApp, superUser, superPass)
	creds := validCredsPayload()
	creds["type"] = "sqlserver"
	body, _ := json.Marshal(creds)
	req, _ := http.NewRequest("POST", "/admin/creds", bytes.NewReader(body))
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "Incorrect db type")
}

func TestCreateCreds_Fail_BadJSON(t *testing.T) {
	resetDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := loginAndGetToken(t, TestApp, superUser, superPass)
	req, _ := http.NewRequest("POST", "/admin/creds", bytes.NewBufferString("{badjson}"))
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "Bad request [1]")
}

func TestCreateCreds_Fail_MissingRequiredFields(t *testing.T) {
	resetDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := loginAndGetToken(t, TestApp, superUser, superPass)
	creds := validCredsPayload()
	delete(creds, "db_password")
	body, _ := json.Marshal(creds)
	req, _ := http.NewRequest("POST", "/admin/creds", bytes.NewReader(body))
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "Bad request")
}

func TestCreateCreds_Fail_InvalidBase64Password(t *testing.T) {
	resetDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := loginAndGetToken(t, TestApp, superUser, superPass)
	creds := validCredsPayload()
	creds["db_password"] = "!!!notbase64!!!"
	body, _ := json.Marshal(creds)
	req, _ := http.NewRequest("POST", "/admin/creds", bytes.NewReader(body))
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "Bad request [4]")
}
