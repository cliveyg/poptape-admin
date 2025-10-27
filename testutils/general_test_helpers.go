package testutils

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/cliveyg/poptape-admin/app"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func LoginAndGetToken(t *testing.T, testApp *app.App, username, password string) string {
	loginReq := map[string]string{
		"username": username,
		"password": password,
	}
	body, _ := json.Marshal(loginReq)
	req, err := http.NewRequest("POST", "/admin/login", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create login request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	testApp.Router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("login should return 200, got %d", w.Code)
	}

	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(w.Body).Decode(&out); err != nil {
		t.Fatalf("failed to decode login response: %v", err)
	}
	if out.Token == "" {
		t.Fatalf("login returned empty token")
	}
	return out.Token
}

func SetUserValidated(t *testing.T, testApp *app.App, username string) {
	result := testApp.DB.Model(&app.User{}).Where("username = ?", username).Update("validated", true)
	if result.Error != nil {
		t.Fatalf("failed to set user validated: %v", result.Error)
	}
}

func SetUserInactive(t *testing.T, testApp *app.App, username string) {
	result := testApp.DB.Model(&app.User{}).Where("username = ?", username).Update("active", false)
	if result.Error != nil {
		t.Fatalf("failed to set user inactive: %v", result.Error)
	}
}

var (
	seededRand = rand.New(rand.NewSource(time.Now().UnixNano()))
	randMu     sync.Mutex
)

func RandString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	randMu.Lock()
	defer randMu.Unlock()
	for i := range b {
		b[i] = letters[seededRand.Intn(len(letters))]
	}
	return string(b)
}

func EnsureTestMicroserviceAndCred(t *testing.T, appInstance *app.App, token, dbName, msName, roleName string) string {
	payload := map[string]interface{}{
		"db_name":     dbName,
		"type":        "postgres",
		"url":         "/" + msName,
		"db_username": dbName,
		"db_password": base64.StdEncoding.EncodeToString([]byte("password")),
		"db_port":     "5432",
		"host":        "localhost",
		"role_name":   roleName,
		"ms_name":     msName,
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "/admin/creds", bytes.NewReader(body))
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	appInstance.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	reqMS, _ := http.NewRequest("GET", "/admin/microservices", nil)
	reqMS.Header.Set("y-access-token", token)
	wMS := httptest.NewRecorder()
	appInstance.Router.ServeHTTP(wMS, reqMS)
	require.Equal(t, http.StatusOK, wMS.Code)
	var msResp struct {
		Microservices []struct {
			MicroserviceId string `json:"microservice_id"`
			MSName         string `json:"ms_name"`
		} `json:"microservices"`
	}
	require.NoError(t, json.Unmarshal(wMS.Body.Bytes(), &msResp))
	for _, ms := range msResp.Microservices {
		if ms.MSName == msName {
			return ms.MicroserviceId
		}
	}
	t.Fatalf("could not find microservice_id for %s", msName)
	return ""
}

// APICreateSaveRecordWithFixture creates a save via the public API and returns the save id.
// It sets a MockCommandRunner fixture for the supplied command (e.g. "pg_dump" or "mongodump")
// using the provided fixture filename. This is backward-compatible: tests that call the
// existing APICreateSaveRecord keep the same behaviour.
func APICreateSaveRecordWithFixture(t *testing.T, appInstance *app.App, token, msID, dbName, command, fixture string) string {
	t.Helper()

	// Set up command runner fixture for the requested command.
	appInstance.CommandRunner = &MockCommandRunner{
		T: t,
		Fixtures: map[string]string{
			command: fixture,
		},
	}

	url := fmt.Sprintf("/admin/save/%s/%s?mode=all", msID, dbName)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	appInstance.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "expected 201 Created from /admin/save; body: %s", w.Body.String())

	var resp struct {
		SaveID string `json:"save_id"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.SaveID, "save_id must be present in response")
	return resp.SaveID
}

// APICreateSaveRecord retains the original behaviour for postgres tests.
// It delegates to APICreateSaveRecordWithFixture with the postgres defaults so existing callers are unchanged.
func APICreateSaveRecord(t *testing.T, appInstance *app.App, token, msID, dbName string) string {
	t.Helper()
	return APICreateSaveRecordWithFixture(t, appInstance, token, msID, dbName, "pg_dump", "reviews.dump")
}

func ExtractSavesList(t *testing.T, body []byte) ([]app.SaveRecord, int) {
	var resp struct {
		NoOfSaves int              `json:"no_of_saves"`
		Saves     []app.SaveRecord `json:"saves"`
	}
	require.NoError(t, json.Unmarshal(body, &resp))
	return resp.Saves, resp.NoOfSaves
}

func ListAllSavesExtractSavesList(t *testing.T, body []byte) ([]app.SaveRecord, int) {
	var resp struct {
		NoOfSaves int              `json:"total_saves"`
		Saves     []app.SaveRecord `json:"saves"`
	}
	require.NoError(t, json.Unmarshal(body, &resp))
	return resp.Saves, resp.NoOfSaves
}

func UniqueName(prefix string) string {
	return fmt.Sprintf("%s_%s", prefix, uuid.New().String())
}

// ExtractJSONResponse unmarshals the body of a ResponseRecorder into a map.
func ExtractJSONResponse(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	var out map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &out)
	require.NoError(t, err)
	return out
}

// SetupEncryptPasswordMock replaces app.EncryptCredPass with a mock that always returns a fixed encrypted value.
// Returns a cleanup function to restore the original after the test.
func SetupEncryptPasswordMock() func() {
	original := app.EncryptCredPass
	app.EncryptCredPass = func(cr *app.Cred) error {
		cr.DBPassword = "mocked_encrypted_password"
		return nil
	}
	return func() { app.EncryptCredPass = original }
}

func CreateTestUserBasic(name string) app.User {
	return app.User{
		AdminId:   uuid.New(),
		Username:  name,
		Active:    true,
		Validated: true,
		Roles:     []app.Role{{Name: "admin"}}, // Always at least one role
	}
}

// NewSignupPayload returns a signup payload with password base64 encoded.
func NewSignupPayload(username, password, confirm string) map[string]string {
	// Only encode if password is not already encoded
	encode := func(s string) string {
		if _, err := base64.StdEncoding.DecodeString(s); err != nil {
			return base64.StdEncoding.EncodeToString([]byte(s))
		}
		return s
	}
	return map[string]string{
		"username":         username,
		"password":         encode(password),
		"confirm_password": encode(confirm),
	}
}
