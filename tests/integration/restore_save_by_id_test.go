package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/cliveyg/poptape-admin/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestRestorePostgresBySaveID_HappyPath(t *testing.T) {
	a := testutils.SetupTestApp(t)

	testutils.ResetPostgresDB(t, a)
	testutils.ResetMongoDB(t, a)

	super := os.Getenv("SUPERUSER")
	require.NotEmpty(t, super, "SUPERUSER env required")
	token := testutils.LoginAndGetToken(t, a, super, os.Getenv("SUPERPASS"))

	pgDB := os.Getenv("POSTGRES_DBNAME")
	require.NotEmpty(t, pgDB, "POSTGRES_DBNAME env required")

	msName := testutils.UniqueName("integ_pg_ms")
	msID := testutils.EnsureTestMicroserviceAndCred(t, a, token, pgDB, msName, "apiserver")
	require.NotEmpty(t, msID)

	saveID := testutils.APICreateSaveRecord(t, a, token, msID, pgDB)
	require.NotEmpty(t, saveID)

	loadURL := "/admin/load/data/" + saveID
	req, _ := http.NewRequest("GET", loadURL, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	a.Router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(bytes.NewReader(w.Body.Bytes())).Decode(&resp))
	require.Contains(t, resp["message"].(string), "Postgres restore succeeded")
}

func TestRestoreMongoBySaveID_HappyPath(t *testing.T) {
	a := testutils.SetupTestApp(t)

	testutils.ResetPostgresDB(t, a)
	testutils.ResetMongoDB(t, a)

	super := os.Getenv("SUPERUSER")
	require.NotEmpty(t, super, "SUPERUSER env required")
	token := testutils.LoginAndGetToken(t, a, super, os.Getenv("SUPERPASS"))

	mongoDB := os.Getenv("MONGO_DBNAME")
	require.NotEmpty(t, mongoDB, "MONGO_DBNAME env required")

	payload := testutils.DefaultCreateCredsPayload()
	msName := testutils.UniqueName("integ_mongo_ms")
	payload["ms_name"] = msName
	payload["db_name"] = mongoDB
	payload["role_name"] = "items"

	bodyBytes, _ := json.Marshal(payload)
	reqCreate, _ := http.NewRequest("POST", "/admin/creds", bytes.NewReader(bodyBytes))
	reqCreate.Header.Set("y-access-token", token)
	reqCreate.Header.Set("Content-Type", "application/json")
	wCreate := httptest.NewRecorder()
	a.Router.ServeHTTP(wCreate, reqCreate)
	require.Equal(t, http.StatusCreated, wCreate.Code)

	reqMS, _ := http.NewRequest("GET", "/admin/microservices", nil)
	reqMS.Header.Set("y-access-token", token)
	wMS := httptest.NewRecorder()
	a.Router.ServeHTTP(wMS, reqMS)
	require.Equal(t, http.StatusOK, wMS.Code)
	var msResp struct {
		Microservices []struct {
			MicroserviceId string `json:"microservice_id"`
			MSName         string `json:"ms_name"`
		} `json:"microservices"`
	}
	require.NoError(t, json.Unmarshal(wMS.Body.Bytes(), &msResp))
	var msID string
	for _, ms := range msResp.Microservices {
		if ms.MSName == msName {
			msID = ms.MicroserviceId
			break
		}
	}
	require.NotEmpty(t, msID)

	saveID := testutils.APICreateSaveRecordWithFixture(t, a, token, msID, mongoDB, "mongodump", "fotos.dump")
	require.NotEmpty(t, saveID)

	loadURL := "/admin/load/data/" + saveID
	req, _ := http.NewRequest("GET", loadURL, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	a.Router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Contains(t, resp["message"].(string), "Mongo restore succeeded")
}

func TestRestoreBySaveID_InvalidUUID(t *testing.T) {
	a := testutils.SetupTestApp(t)
	testutils.ResetPostgresDB(t, a)
	testutils.ResetMongoDB(t, a)

	super := os.Getenv("SUPERUSER")
	require.NotEmpty(t, super, "SUPERUSER env required")
	token := testutils.LoginAndGetToken(t, a, super, os.Getenv("SUPERPASS"))

	loadURL := "/admin/load/data/not-a-uuid"
	req, _ := http.NewRequest("GET", loadURL, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	a.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRestoreBySaveID_SaveNotFound(t *testing.T) {
	a := testutils.SetupTestApp(t)
	testutils.ResetPostgresDB(t, a)
	testutils.ResetMongoDB(t, a)

	super := os.Getenv("SUPERUSER")
	require.NotEmpty(t, super, "SUPERUSER env required")
	token := testutils.LoginAndGetToken(t, a, super, os.Getenv("SUPERPASS"))

	rid := uuid.New().String()
	loadURL := "/admin/load/data/" + rid
	req, _ := http.NewRequest("GET", loadURL, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	a.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestRestoreBySaveID_GridFSFileMissing(t *testing.T) {
	a := testutils.SetupTestApp(t)
	testutils.ResetPostgresDB(t, a)
	testutils.ResetMongoDB(t, a)

	super := os.Getenv("SUPERUSER")
	require.NotEmpty(t, super, "SUPERUSER env required")
	token := testutils.LoginAndGetToken(t, a, super, os.Getenv("SUPERPASS"))

	mongoDB := os.Getenv("MONGO_DBNAME")
	require.NotEmpty(t, mongoDB, "MONGO_DBNAME env required")

	payload := testutils.DefaultCreateCredsPayload()
	msName := testutils.UniqueName("integ_missing_file_ms")
	payload["ms_name"] = msName
	payload["db_name"] = mongoDB
	payload["role_name"] = "items"

	bodyBytes, _ := json.Marshal(payload)
	reqCreate, _ := http.NewRequest("POST", "/admin/creds", bytes.NewReader(bodyBytes))
	reqCreate.Header.Set("y-access-token", token)
	reqCreate.Header.Set("Content-Type", "application/json")
	wCreate := httptest.NewRecorder()
	a.Router.ServeHTTP(wCreate, reqCreate)
	require.Equal(t, http.StatusCreated, wCreate.Code)

	var cred app.Cred
	res := a.DB.Where("db_name = ?", mongoDB).First(&cred)
	require.NoError(t, res.Error)

	var ms app.Microservice
	res = a.DB.Where("ms_name = ?", msName).First(&ms)
	require.NoError(t, res.Error)

	saveId := uuid.New()
	sr := app.SaveRecord{
		SaveId:         saveId,
		MicroserviceId: ms.MicroserviceId,
		CredId:         cred.CredId,
		DBName:         mongoDB,
		Table:          "",
		SavedBy:        "integration_test",
		Version:        1,
		Dataset:        0,
		Mode:           "all",
		Valid:          true,
		Type:           cred.Type,
		Size:           123,
	}
	res = a.DB.Create(&sr)
	require.NoError(t, res.Error)

	loadURL := "/admin/load/data/" + saveId.String()
	req, _ := http.NewRequest("GET", loadURL, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	a.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestRestoreBySaveID_ForbiddenUser(t *testing.T) {
	a := testutils.SetupTestApp(t)
	testutils.ResetPostgresDB(t, a)
	testutils.ResetMongoDB(t, a)

	super := os.Getenv("SUPERUSER")
	require.NotEmpty(t, super, "SUPERUSER env required")
	superToken := testutils.LoginAndGetToken(t, a, super, os.Getenv("SUPERPASS"))

	pgDB := os.Getenv("POSTGRES_DBNAME")
	require.NotEmpty(t, pgDB, "POSTGRES_DBNAME env required")

	msName := testutils.UniqueName("integ_forbid_ms")
	msID := testutils.EnsureTestMicroserviceAndCred(t, a, superToken, pgDB, msName, "apiserver")
	require.NotEmpty(t, msID)

	saveID := testutils.APICreateSaveRecord(t, a, superToken, msID, pgDB)
	require.NotEmpty(t, saveID)

	var role app.Role
	res := a.DB.First(&role, "name = ?", "aws")
	require.NoError(t, res.Error)

	newUser := app.User{
		AdminId:   uuid.New(),
		Username:  testutils.UniqueName("forbid_user"),
		Password:  []byte("irrelevant"),
		Active:    true,
		Validated: true,
		Roles:     []app.Role{role},
	}
	res = a.DB.Create(&newUser)
	require.NoError(t, res.Error)

	testutils.SetUserValidated(t, a, newUser.Username)

	token, err := utils.GenerateToken(newUser.Username, newUser.AdminId)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	loadURL := "/admin/load/data/" + saveID
	req, _ := http.NewRequest("GET", loadURL, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	a.Router.ServeHTTP(w, req)

	require.Equal(t, http.StatusForbidden, w.Code)
}
