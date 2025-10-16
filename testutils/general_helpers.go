package testutils

import (
	"bytes"
	"encoding/json"
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

func InsertSaveRecord(t *testing.T, testApp *app.App, rec app.SaveRecord) {
	require.NotNil(t, testApp)
	require.NotNil(t, testApp.DB)
	require.NoError(t, testApp.DB.Create(&rec).Error)
}

func NewTestSaveRecord() app.SaveRecord {
	now := time.Now().UTC()
	return app.SaveRecord{
		SaveId:         uuid.New(),
		MicroserviceId: uuid.New(),
		CredId:         uuid.New(),
		DBName:         "db_" + uuid.NewString()[:8],
		Table:          "sometable",
		SavedBy:        "superuser",
		Version:        1,
		Dataset:        0,
		Mode:           "all",
		Valid:          true,
		Type:           "mongo",
		Size:           1234,
		Notes:          "test note",
		Created:        now,
		Updated:        now,
	}
}

func ExtractSavesList(t *testing.T, body []byte) ([]app.SaveRecord, int) {
	var resp struct {
		TotalSaves int              `json:"total_saves"`
		Saves      []app.SaveRecord `json:"saves"`
	}
	require.NoError(t, json.Unmarshal(body, &resp))
	return resp.Saves, resp.TotalSaves
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
