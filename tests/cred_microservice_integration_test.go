package tests

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"github.com/cliveyg/poptape-admin/app"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestCreateCreds_HappyPath_Super(t *testing.T) {
	resetDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := loginAndGetToken(t, TestApp, superUser, superPass)

	payload := map[string]interface{}{
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
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "/admin/creds", bytes.NewReader(body))
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
	token := loginAndGetToken(t, TestApp, superUser, superPass)

	// Create and validate an admin user
	username := "admincreds_" + RandString(6)
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

	payload := map[string]interface{}{
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
	body, _ = json.Marshal(payload)
	req2, _ := http.NewRequest("POST", "/admin/creds", bytes.NewReader(body))
	req2.Header.Set("y-access-token", adminToken)
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w2, req2)
	require.Equal(t, http.StatusCreated, w2.Code)
	require.Contains(t, w2.Body.String(), "Creds created; credId is [")
}

func TestCreateCreds_Forbidden_NonPrivilegedRole(t *testing.T) {
	resetDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	token := loginAndGetToken(t, TestApp, superUser, superPass)

	// Create/validate user, remove "admin" role, add "aws"
	username := "awscreds_" + RandString(6)
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
	var user app.User
	require.NoError(t, TestApp.DB.Where("username = ?", username).First(&user).Error)
	addRoleReq, _ := http.NewRequest("POST", "/admin/user/"+user.AdminId.String()+"/aws", nil)
	addRoleReq.Header.Set("y-access-token", token)
	w2 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w2, addRoleReq)
	require.Equal(t, http.StatusCreated, w2.Code)
	removeRoleReq, _ := http.NewRequest("DELETE", "/admin/user/"+user.AdminId.String()+"/admin", nil)
	removeRoleReq.Header.Set("y-access-token", token)
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

	payload := map[string]interface{}{
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
	body, _ = json.Marshal(payload)
	req2, _ := http.NewRequest("POST", "/admin/creds", bytes.NewReader(body))
	req2.Header.Set("y-access-token", awsToken)
	req2.Header.Set("Content-Type", "application/json")
	w2 = httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w2, req2)
	require.Equal(t, http.StatusForbidden, w2.Code)
	require.Contains(t, w2.Body.String(), "Forbidden")
}

func TestCreateCreds_Unauthorized_NoToken(t *testing.T) {
	resetDB(t, TestApp)
	payload := map[string]interface{}{
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
	body, _ := json.Marshal(payload)
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
	token := loginAndGetToken(t, TestApp, superUser, superPass)
	payload := map[string]interface{}{
		"db_name":     "poptape_items",
		"type":        "sqlserver", // invalid
		"url":         "/items",
		"db_username": "poptape_items",
		"db_password": "cGFzc3dvcmQ=",
		"db_port":     "27017",
		"host":        "poptape-items-mongodb-1",
		"role_name":   "items",
		"ms_name":     "items",
	}
	body, _ := json.Marshal(payload)
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
	token := loginAndGetToken(t, TestApp, superUser, superPass)
	// Missing db_password
	payload := map[string]interface{}{
		"db_name":     "poptape_items",
		"type":        "mongo",
		"url":         "/items",
		"db_username": "poptape_items",
		"db_port":     "27017",
		"host":        "poptape-items-mongodb-1",
		"role_name":   "items",
		"ms_name":     "items",
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "/admin/creds", bytes.NewReader(body))
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	// Could fail on a different bind step, so just require "Bad request"
	require.Contains(t, w.Body.String(), "Bad request")
}

func TestCreateCreds_Fail_InvalidBase64Password(t *testing.T) {
	resetDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	token := loginAndGetToken(t, TestApp, superUser, superPass)
	payload := map[string]interface{}{
		"db_name":     "poptape_items",
		"type":        "mongo",
		"url":         "/items",
		"db_username": "poptape_items",
		"db_password": "!!!notbase64!!!",
		"db_port":     "27017",
		"host":        "poptape-items-mongodb-1",
		"role_name":   "items",
		"ms_name":     "items",
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "/admin/creds", bytes.NewReader(body))
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "Bad request [4]")
}
