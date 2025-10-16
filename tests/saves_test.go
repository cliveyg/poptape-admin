package tests

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestListAllSaves_HappyPath_Super(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	testutils.ResetMongoDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	dbName := "poptape_reviews"
	msName := "reviews"
	roleName := "reviews"

	msID := testutils.EnsureTestMicroserviceAndCred(t, TestApp, token, dbName, msName, roleName)
	saveID1 := testutils.APICreateSaveRecord(t, TestApp, token, msID, dbName)
	saveID2 := testutils.APICreateSaveRecord(t, TestApp, token, msID, dbName)

	req, _ := http.NewRequest("GET", "/admin/saves", nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	saves, total := testutils.ExtractSavesListTotal(t, w.Body.Bytes())
	require.Len(t, saves, 2)
	require.Equal(t, 2, total)
	saveIDs := []string{saves[0].SaveId.String(), saves[1].SaveId.String()}
	require.Contains(t, saveIDs, saveID1)
	require.Contains(t, saveIDs, saveID2)
	testutils.ResetPostgresDB(t, TestApp)
}

func TestListAllSaves_NoRecordsFound_Returns404(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	testutils.ResetMongoDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	req, _ := http.NewRequest("GET", "/admin/saves", nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusNotFound, w.Code)
	require.Contains(t, w.Body.String(), "No save records found")
}

func TestListAllSaves_BadMetaValue_Returns400(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	testutils.ResetMongoDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	req, _ := http.NewRequest("GET", "/admin/saves?meta=badvalue", nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "Invalid meta value")
}

func TestListAllSaves_Unauthorized_NoToken(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	testutils.ResetMongoDB(t, TestApp)
	req, _ := http.NewRequest("GET", "/admin/saves", nil)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListAllSaves_Forbidden_NonSuperRole(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	superToken := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	// Create a non-super user (e.g. aws)
	username := "aws_saves_" + testutils.RandString(6)
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

	// Add AWS role, remove admin if present
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

	// Login as AWS user
	loginReq := map[string]string{
		"username": username,
		"password": base64.StdEncoding.EncodeToString([]byte(password)),
	}
	loginBody, _ := json.Marshal(loginReq)
	reqLogin, _ := http.NewRequest("POST", "/admin/login", bytes.NewReader(loginBody))
	reqLogin.Header.Set("Content-Type", "application/json")
	wLogin := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(wLogin, reqLogin)
	require.Equal(t, http.StatusOK, wLogin.Code)
	var out struct{ Token string }
	require.NoError(t, json.NewDecoder(wLogin.Body).Decode(&out))
	awsToken := out.Token

	// Try to list saves as AWS user (should be forbidden)
	req4, _ := http.NewRequest("GET", "/admin/saves", nil)
	req4.Header.Set("y-access-token", awsToken)
	w4 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w4, req4)
	require.Equal(t, http.StatusForbidden, w4.Code)
	require.Contains(t, w4.Body.String(), "Forbidden")
}
