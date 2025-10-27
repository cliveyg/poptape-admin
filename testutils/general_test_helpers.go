package testutils

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"math/rand"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/mongo/gridfs"
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
// using the provided fixture filename.
//
// When command == "mongodump" this helper also automatically installs safe MockHooks
// for WriteMongoOut, CreateGridFSUploadStream, CopyToGridFS and SaveWithAutoVersion so that
// the test will not attempt real Mongo connections or GridFS writes. The original Hooks are
// restored via t.Cleanup after the function returns.
func APICreateSaveRecordWithFixture(t *testing.T, appInstance *app.App, token, msID, dbName, command, fixture string) string {
	t.Helper()

	// Set up command runner fixture for the requested command.
	appInstance.CommandRunner = &MockCommandRunner{
		T: t,
		Fixtures: map[string]string{
			command: fixture,
		},
	}

	// If using mongodump, automatically stub hooks to avoid any real Mongo driver usage.
	if command == "mongodump" {
		origHooks := appInstance.Hooks
		t.Cleanup(func() {
			appInstance.Hooks = origHooks
		})

		// Create test hooks that mirror the unit-test mocks: don't connect to real Mongo,
		// consume the mongodump fixture stream and return counts / success.
		hooks := &MockHooks{}
		// Prevent WriteMongoOut from creating a mongo.Client and pinging — return success.
		hooks.WriteMongoOutFunc = func(args *app.WriteMongoArgs) (string, error) {
			return "OK", nil
		}
		// Prevent GridFS writes: return nil upload stream (backup code will still call CopyToGridFS)
		hooks.CreateGridFSUploadStreamFunc = func(db, filename string, metadata map[string]interface{}) (*gridfs.UploadStream, error) {
			return nil, nil
		}
		// CopyToGridFS consumes the stdout (fixture) and returns number of bytes read.
		hooks.CopyToGridFSFunc = func(uploadStream *gridfs.UploadStream, stdout io.Reader, logPrefix string) (int64, error) {
			n, err := io.Copy(io.Discard, stdout)
			return n, err
		}
		// Ensure saving the SaveRecord doesn't error during tests
		hooks.SaveWithAutoVersionFunc = func(sr *app.SaveRecord) error {
			// If an app.Hooks.SaveWithAutoVersion is required by other tests to write DB records,
			// the original is restored by t.Cleanup above.
			return nil
		}
		appInstance.Hooks = hooks
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
