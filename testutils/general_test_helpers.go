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
	testApp.Log.Info().Msgf("%%%%%%% ret code is [%d]", w.Code)
	if w.Code != http.StatusOK {
		t.Fatalf("login should return 200, got %d", w.Code)
	}

	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(w.Body).Decode(&out); err != nil {
		t.Fatalf("failed to decode login response: %v", err)
	}
	testApp.Log.Info().Msg("%%%%%%% DECODED OK")
	if out.Token == "" {
		t.Fatalf("login returned empty token")
	}
	testApp.Log.Info().Msg("%%%%%%% SUD BE RETURNING TOKEN")
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

func APICreateSaveRecord(t *testing.T, appInstance *app.App, token, msID, dbName string) string {
	appInstance.CommandRunner = &MockCommandRunner{
		T: t,
		Fixtures: map[string]string{
			"pg_dump": "reviews.dump",
		},
	}
	url := fmt.Sprintf("/admin/save/%s/%s?mode=all", msID, dbName)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	appInstance.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)
	var resp struct {
		SaveID string `json:"save_id"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.SaveID)
	return resp.SaveID
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
