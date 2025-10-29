package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/cliveyg/poptape-admin/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// Happy path: Delete SaveRecord + GridFS for Postgres backup
func TestDeleteSaveById_Postgres_HappyPath(t *testing.T) {
	a := testutils.SetupTestApp(t)
	testutils.ResetPostgresDB(t, a)
	testutils.ResetMongoDB(t, a)

	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	token := testutils.LoginAndGetToken(t, a, superUser, superPass)

	pgDB := os.Getenv("POSTGRES_DBNAME")
	msName := testutils.UniqueName("del_pg_ms")
	msID := testutils.EnsureTestMicroserviceAndCred(t, a, token, pgDB, msName, "apiserver")
	saveID := testutils.APICreateSaveRecord(t, a, token, msID, pgDB)

	// Confirm GridFS file exists before deletion
	mongoClient := testutils.TestMongoClient(t)
	defer mongoClient.Disconnect(context.Background())
	filter := bson.M{"metadata.save_id": saveID}
	files, err := mongoClient.Database(pgDB).Collection("fs.files").Find(context.Background(), filter)
	require.NoError(t, err)
	require.True(t, files.Next(context.Background()), "GridFS file should exist before deletion")

	// Delete via API
	url := "/admin/data/" + saveID
	req, _ := http.NewRequest("DELETE", url, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	a.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), "Save record ["+saveID+"] and mongo data deleted")

	// Confirm SaveRecord is deleted from Postgres
	var sr app.SaveRecord
	res := a.DB.Where("save_id = ?", saveID).First(&sr)
	require.Error(t, res.Error)

	// Confirm GridFS file is deleted from MongoDB using testutils helper
	testutils.AssertMongoGridFSDeleted(t, pgDB, saveID)
}

// Happy path: Delete SaveRecord + GridFS for Mongo backup
func TestDeleteSaveById_Mongo_HappyPath(t *testing.T) {
	a := testutils.SetupTestApp(t)
	testutils.ResetPostgresDB(t, a)
	testutils.ResetMongoDB(t, a)

	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	token := testutils.LoginAndGetToken(t, a, superUser, superPass)
	mongoDB := os.Getenv("MONGO_DBNAME")

	payload := testutils.DefaultCreateCredsPayload()
	msName := testutils.UniqueName("del_mongo_ms")
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

	// Confirm GridFS file exists before deletion
	mongoClient := testutils.TestMongoClient(t)
	defer mongoClient.Disconnect(context.Background())
	filter := bson.M{"metadata.save_id": saveID}
	files, err := mongoClient.Database(mongoDB).Collection("fs.files").Find(context.Background(), filter)
	require.NoError(t, err)
	require.True(t, files.Next(context.Background()), "GridFS file should exist before deletion")

	// Delete via API
	url := "/admin/data/" + saveID
	req, _ := http.NewRequest("DELETE", url, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	a.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), "Save record ["+saveID+"] and mongo data deleted")

	// Confirm SaveRecord is deleted from Postgres
	var sr app.SaveRecord
	res := a.DB.Where("save_id = ?", saveID).First(&sr)
	require.Error(t, res.Error)

	// Confirm GridFS file is deleted from MongoDB using testutils helper
	testutils.AssertMongoGridFSDeleted(t, mongoDB, saveID)
}

// Error: Bad UUID
func TestDeleteSaveById_BadUUID(t *testing.T) {
	a := testutils.SetupTestApp(t)
	testutils.ResetPostgresDB(t, a)
	testutils.ResetMongoDB(t, a)

	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	token := testutils.LoginAndGetToken(t, a, superUser, superPass)
	url := "/admin/data/not-a-uuid"
	req, _ := http.NewRequest("DELETE", url, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	a.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "Bad request")
}

// Error: SaveRecord not found
func TestDeleteSaveById_SaveNotFound(t *testing.T) {
	a := testutils.SetupTestApp(t)
	testutils.ResetPostgresDB(t, a)
	testutils.ResetMongoDB(t, a)

	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	token := testutils.LoginAndGetToken(t, a, superUser, superPass)
	randomId := uuid.New().String()
	url := "/admin/data/" + randomId
	req, _ := http.NewRequest("DELETE", url, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	a.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusNotFound, w.Code)
	require.Contains(t, w.Body.String(), "SaveRecord record not found")
}

// Error: GridFS file missing in MongoDB
func TestDeleteSaveById_GridFSFileMissing(t *testing.T) {
	a := testutils.SetupTestApp(t)
	testutils.ResetPostgresDB(t, a)
	testutils.ResetMongoDB(t, a)

	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	token := testutils.LoginAndGetToken(t, a, superUser, superPass)
	mongoDB := os.Getenv("MONGO_DBNAME")

	payload := testutils.DefaultCreateCredsPayload()
	msName := testutils.UniqueName("del_missing_file_ms")
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

	saveID := uuid.New()
	sr := app.SaveRecord{
		SaveId:         saveID,
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

	url := "/admin/data/" + saveID.String()
	req, _ := http.NewRequest("DELETE", url, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	a.Router.ServeHTTP(w, req)
	// Should fail with internal error as no file is found in GridFS
	require.Equal(t, http.StatusInternalServerError, w.Code)
	require.Contains(t, w.Body.String(), "Something went donk")
}

// Error: Forbidden user (role not allowed)
func TestDeleteSaveById_ForbiddenUser(t *testing.T) {
	a := testutils.SetupTestApp(t)
	testutils.ResetPostgresDB(t, a)
	testutils.ResetMongoDB(t, a)

	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	superToken := testutils.LoginAndGetToken(t, a, superUser, superPass)
	pgDB := os.Getenv("POSTGRES_DBNAME")
	msName := testutils.UniqueName("del_forbid_ms")
	msID := testutils.EnsureTestMicroserviceAndCred(t, a, superToken, pgDB, msName, "apiserver")
	saveID := testutils.APICreateSaveRecord(t, a, superToken, msID, pgDB)

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

	url := "/admin/data/" + saveID
	req, _ := http.NewRequest("DELETE", url, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	a.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusForbidden, w.Code)
	require.Contains(t, w.Body.String(), "Forbidden")
}

// Error: Unauthorized (no token)
func TestDeleteSaveById_Unauthorized_NoToken(t *testing.T) {
	a := testutils.SetupTestApp(t)
	testutils.ResetPostgresDB(t, a)
	testutils.ResetMongoDB(t, a)
	url := "/admin/data/" + uuid.New().String()
	req, _ := http.NewRequest("DELETE", url, nil)
	w := httptest.NewRecorder()
	a.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

// Error: Forbidden (user without super/admin role)
func TestDeleteSaveById_Forbidden_NonPrivilegedRole(t *testing.T) {
	a := testutils.SetupTestApp(t)
	testutils.ResetPostgresDB(t, a)
	testutils.ResetMongoDB(t, a)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	token := testutils.LoginAndGetToken(t, a, superUser, superPass)

	username := "awsuser_" + testutils.RandString(6)
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
	a.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)
	testutils.SetUserValidated(t, a, username)
	var user app.User
	require.NoError(t, a.DB.Where("username = ?", username).First(&user).Error)
	addRoleReq, _ := http.NewRequest("POST", "/admin/user/"+user.AdminId.String()+"/aws", nil)
	addRoleReq.Header.Set("y-access-token", token)
	w2 := httptest.NewRecorder()
	a.Router.ServeHTTP(w2, addRoleReq)
	require.Equal(t, http.StatusCreated, w2.Code)
	removeRoleReq, _ := http.NewRequest("DELETE", "/admin/user/"+user.AdminId.String()+"/admin", nil)
	removeRoleReq.Header.Set("y-access-token", token)
	w3 := httptest.NewRecorder()
	a.Router.ServeHTTP(w3, removeRoleReq)
	require.Equal(t, http.StatusGone, w3.Code)
	loginReq := map[string]string{
		"username": username,
		"password": base64.StdEncoding.EncodeToString([]byte(password)),
	}
	loginBody, _ := json.Marshal(loginReq)
	reqLogin, _ := http.NewRequest("POST", "/admin/login", bytes.NewReader(loginBody))
	reqLogin.Header.Set("Content-Type", "application/json")
	wLogin := httptest.NewRecorder()
	a.Router.ServeHTTP(wLogin, reqLogin)
	require.Equal(t, http.StatusOK, wLogin.Code)
	var out struct{ Token string }
	require.NoError(t, json.NewDecoder(wLogin.Body).Decode(&out))
	awsToken := out.Token

	url := "/admin/data/" + uuid.New().String()
	req4, _ := http.NewRequest("DELETE", url, nil)
	req4.Header.Set("y-access-token", awsToken)
	w4 := httptest.NewRecorder()
	a.Router.ServeHTTP(w4, req4)
	require.Equal(t, http.StatusForbidden, w4.Code)
	require.Contains(t, w4.Body.String(), "Forbidden")
}
