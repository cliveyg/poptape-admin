package tests

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"github.com/google/uuid"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/stretchr/testify/require"
)

func createCredViaAPI(t *testing.T, token string) string {
	uniq := testutils.RandString(8)
	payload := map[string]interface{}{
		"db_name":     "db_" + uniq,
		"type":        "mongo",
		"url":         "/" + uniq,
		"db_username": "user_" + uniq,
		"db_password": randomB64Password(),
		"db_port":     "27017",
		"host":        "host-" + uniq,
		"role_name":   "admin",
		"ms_name":     "ms_" + uniq,
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "/admin/creds", bytes.NewReader(body))
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)
	var out struct{ Message string }
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))

	re := regexp.MustCompile(`[a-fA-F0-9\-]{36}`)
	credId := re.FindString(out.Message)
	t.Logf("Extracted credId: '%s' (len=%d) from message: %q", credId, len(credId), out.Message)
	require.True(t, len(credId) == 36, "Extracted credId is not a 36-character UUID: '%s'", credId)
	return credId
}

func randomB64Password() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	raw := make([]byte, 16)
	for i := range raw {
		raw[i] = byte(r.Intn(26) + 65)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func uniqueCredsPayload() map[string]interface{} {
	uniq := testutils.RandString(8)
	return map[string]interface{}{
		"db_name":     "db_" + uniq,
		"type":        "mongo",
		"url":         "/" + uniq,
		"db_username": "user_" + uniq,
		"db_password": randomB64Password(),
		"db_port":     "27017",
		"host":        "host-" + uniq,
		"role_name":   "role_" + uniq,
		"ms_name":     "ms_" + uniq,
	}
}

func extractCredsList(t *testing.T, body []byte) []app.Cred {
	var resp struct {
		Creds []app.Cred `json:"creds"`
	}
	require.NoError(t, json.Unmarshal(body, &resp))
	return resp.Creds
}

func TestCreateCreds_HappyPath_Super(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	payload := uniqueCredsPayload()
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
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	superToken := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	adminUsername := "admincreds_" + testutils.RandString(6)
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

	payload := uniqueCredsPayload()
	body, _ = json.Marshal(payload)
	req3, _ := http.NewRequest("POST", "/admin/creds", bytes.NewReader(body))
	req3.Header.Set("y-access-token", adminToken)
	req3.Header.Set("Content-Type", "application/json")
	w3 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w3, req3)
	require.Equal(t, http.StatusCreated, w3.Code)
	require.Contains(t, w3.Body.String(), "Creds created; credId is [")
}

func TestCreateCreds_Forbidden_NonPrivilegedRole(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	superToken := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	username := "awscreds_" + testutils.RandString(6)
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

	payload := uniqueCredsPayload()
	body, _ = json.Marshal(payload)
	req4, _ := http.NewRequest("POST", "/admin/creds", bytes.NewReader(body))
	req4.Header.Set("y-access-token", awsToken)
	req4.Header.Set("Content-Type", "application/json")
	w4 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w4, req4)
	require.Equal(t, http.StatusForbidden, w4.Code)
	require.Contains(t, w4.Body.String(), "Forbidden")
}

func TestCreateCreds_Unauthorized_NoToken(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	payload := uniqueCredsPayload()
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "/admin/creds", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCreateCreds_Fail_InvalidDBType(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)
	payload := uniqueCredsPayload()
	payload["type"] = "sqlserver"
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
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)
	req, _ := http.NewRequest("POST", "/admin/creds", bytes.NewBufferString("{badjson}"))
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "Bad request [1]")
}

func TestCreateCreds_Fail_MissingRequiredFields(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)
	payload := uniqueCredsPayload()
	delete(payload, "db_password")
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "/admin/creds", bytes.NewReader(body))
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "Bad request")
}

func TestCreateCreds_Fail_InvalidBase64Password(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)
	payload := uniqueCredsPayload()
	payload["db_password"] = "!!!notbase64!!!"
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "/admin/creds", bytes.NewReader(body))
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "Bad request [4]")
}

func TestCreateCreds_Fail_MicroserviceBind(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	uniq := testutils.RandString(8)
	// Omit "ms_name" to trigger MsIn bind failure (Bad request [2])
	payload := map[string]interface{}{
		"db_name":     "db_" + uniq,
		"type":        "mongo",
		"url":         "/" + uniq,
		"db_username": "user_" + uniq,
		"db_password": randomB64Password(),
		"db_port":     "27017",
		"host":        "host-" + uniq,
		"role_name":   "role_" + uniq, // present, so will get to MsIn
		// "ms_name":     "ms_" + uniq, // <--- intentionally omitted
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "/admin/creds", bytes.NewReader(body))
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "Bad request [2]")
}

func TestCreateCreds_Fail_RoleBind(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	uniq := testutils.RandString(8)
	// Omit "role_name" to trigger Role bind failure (Bad request [3])
	payload := map[string]interface{}{
		"db_name":     "db_" + uniq,
		"type":        "mongo",
		"url":         "/" + uniq,
		"db_username": "user_" + uniq,
		"db_password": randomB64Password(),
		"db_port":     "27017",
		"host":        "host-" + uniq,
		"ms_name":     "ms_" + uniq, // present so MsIn binds fine
		// "role_name":   "role_" + uniq, // <--- intentionally omitted
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "/admin/creds", bytes.NewReader(body))
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "Bad request [3]")
}

func TestFetchCredsById_HappyPath_Super(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)
	credId := createCredViaAPI(t, token)

	url := "/admin/creds/" + credId
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Creds *app.Cred `json:"creds"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotNil(t, resp.Creds)
	require.Equal(t, credId, resp.Creds.CredId.String())
	require.Equal(t, "XXXXX", resp.Creds.DBPassword)
}

func TestFetchCredsById_HappyPath_Admin(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	superToken := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	adminUsername := "adminfetch_" + testutils.RandString(6)
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

	credId := createCredViaAPI(t, superToken)
	url := "/admin/creds/" + credId
	req3, _ := http.NewRequest("GET", url, nil)
	req3.Header.Set("y-access-token", adminToken)
	w3 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w3, req3)

	require.Equal(t, http.StatusOK, w3.Code)
	var resp struct {
		Creds *app.Cred `json:"creds"`
	}
	require.NoError(t, json.Unmarshal(w3.Body.Bytes(), &resp))
	require.NotNil(t, resp.Creds)
	require.Equal(t, credId, resp.Creds.CredId.String())
	require.Equal(t, "XXXXX", resp.Creds.DBPassword)
}

func TestFetchCredsById_Forbidden_NonPrivilegedRole(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	superToken := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	username := "awsfetch_" + testutils.RandString(6)
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

	credId := createCredViaAPI(t, superToken)
	url := "/admin/creds/" + credId
	req4, _ := http.NewRequest("GET", url, nil)
	req4.Header.Set("y-access-token", awsToken)
	w4 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w4, req4)
	require.Equal(t, http.StatusForbidden, w4.Code)
	require.Contains(t, w4.Body.String(), "Forbidden")
}

func TestFetchCredsById_Unauthorized_NoToken(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)
	credId := createCredViaAPI(t, token)
	url := "/admin/creds/" + credId
	req, _ := http.NewRequest("GET", url, nil)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestFetchCredsById_BadUUID(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	req, _ := http.NewRequest("GET", "/admin/creds/not-a-uuid", nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "Bad request")
}

func TestFetchCredsById_NotFound(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	randomId := uuid.New().String()
	req, _ := http.NewRequest("GET", "/admin/creds/"+randomId, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusNotFound, w.Code)
	require.Contains(t, w.Body.String(), "Creds not found")
}

func TestListAllCreds_HappyPath_Super(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	// Create two creds via API
	id1 := createCredViaAPI(t, token)
	id2 := createCredViaAPI(t, token)

	req, _ := http.NewRequest("GET", "/admin/creds", nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	creds := extractCredsList(t, w.Body.Bytes())
	require.Len(t, creds, 2)
	ids := []string{creds[0].CredId.String(), creds[1].CredId.String()}
	require.Contains(t, ids, id1)
	require.Contains(t, ids, id2)
	for _, c := range creds {
		require.Equal(t, "XXXX", c.DBPassword)
	}
}

func TestListAllCreds_NoCredsFound_Returns404(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	req, _ := http.NewRequest("GET", "/admin/creds", nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)

	require.Equal(t, http.StatusNotFound, w.Code)
	require.Contains(t, w.Body.String(), "No creds found")
}

func TestListAllCreds_Unauthorized_NoToken(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	req, _ := http.NewRequest("GET", "/admin/creds", nil)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListAllCreds_Forbidden_NonSuperRole(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	superToken := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	// Create a new admin user (not super)
	adminUsername := "adminlist_" + testutils.RandString(6)
	adminPassword := "pw"
	userReq := map[string]string{
		"username":         adminUsername,
		"password":         adminPassword, // Not base64: login will base64 it
		"confirm_password": adminPassword,
	}
	body, _ := json.Marshal(userReq)
	req, _ := http.NewRequest("POST", "/admin/user", bytes.NewReader(body))
	req.Header.Set("y-access-token", superToken)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)
	testutils.SetUserValidated(t, TestApp, adminUsername)

	// Login as admin
	loginReq := map[string]string{
		"username": adminUsername,
		"password": base64.StdEncoding.EncodeToString([]byte(adminPassword)),
	}
	loginBody, _ := json.Marshal(loginReq)
	req2, _ := http.NewRequest("POST", "/admin/login", bytes.NewReader(loginBody))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w2, req2)
	require.Equal(t, http.StatusOK, w2.Code)
	var loginResp struct{ Token string }
	require.NoError(t, json.NewDecoder(w2.Body).Decode(&loginResp))
	adminToken := loginResp.Token

	// Try to list creds as admin (should be forbidden)
	req3, _ := http.NewRequest("GET", "/admin/creds", nil)
	req3.Header.Set("y-access-token", adminToken)
	w3 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w3, req3)
	require.Equal(t, http.StatusForbidden, w3.Code)
	require.Contains(t, w3.Body.String(), "Forbidden")
}
