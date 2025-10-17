package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/utils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/gridfs"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
)

func TestBackupPostgres_HappyPath(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	testutils.ResetMongoDB(t, TestApp)

	dbName := "poptape_reviews"

	// Setup MongoDB test client and drop test DB to start clean
	mongoClient := testutils.TestMongoClient(t)
	defer mongoClient.Disconnect(context.Background())
	err := mongoClient.Database(dbName).Drop(context.Background())
	require.NoError(t, err)

	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	// Create reviews cred via API
	payload := map[string]interface{}{
		"db_name":     dbName,
		"type":        "postgres",
		"url":         "/reviews",
		"db_username": "poptape_reviews",
		"db_password": base64.StdEncoding.EncodeToString([]byte("password")),
		"db_port":     "5432",
		"host":        "poptape-reviews-db-1",
		"role_name":   "reviews",
		"ms_name":     "reviews",
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "/admin/creds", bytes.NewReader(body))
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)
	var resp struct{ Message string }
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	// Get microservice_id for "reviews" from API
	reqMS, _ := http.NewRequest("GET", "/admin/microservices", nil)
	reqMS.Header.Set("y-access-token", token)
	wMS := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(wMS, reqMS)
	require.Equal(t, http.StatusOK, wMS.Code)
	var msResp struct {
		Microservices []struct {
			MicroserviceId string `json:"microservice_id"`
			MSName         string `json:"ms_name"`
			CreatedBy      string `json:"created_by"`
			Created        string `json:"created"`
		} `json:"microservices"`
	}
	require.NoError(t, json.Unmarshal(wMS.Body.Bytes(), &msResp))
	var msID string
	for _, ms := range msResp.Microservices {
		if ms.MSName == "reviews" {
			msID = ms.MicroserviceId
			break
		}
	}
	require.NotEmpty(t, msID, "could not find microservice_id for reviews")

	// Mock CommandRunner for pg_dump with the correct fixture for postgres
	TestApp.CommandRunner = &testutils.MockCommandRunner{
		T: t,
		Fixtures: map[string]string{
			"pg_dump": "reviews.dump", // must be in testutils/fixtures/
		},
	}

	// Call the backup endpoint
	url := fmt.Sprintf("/admin/save/%s/%s?mode=all", msID, dbName)
	req2, _ := http.NewRequest("GET", url, nil)
	req2.Header.Set("y-access-token", token)
	w2 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w2, req2)
	require.Equal(t, http.StatusCreated, w2.Code)

	var backupResp struct {
		Message   string `json:"message"`
		NoOfBytes int64  `json:"no_of_bytes"`
		SaveID    string `json:"save_id"`
	}
	require.NoError(t, json.Unmarshal(w2.Body.Bytes(), &backupResp))
	require.Contains(t, backupResp.Message, "postgres db saved")
	require.NotZero(t, backupResp.NoOfBytes)
	require.NotEmpty(t, backupResp.SaveID)

	// Check save record exists in saverecords table
	var saveRec app.SaveRecord
	saveUUID, err := uuid.Parse(backupResp.SaveID)
	require.NoError(t, err)
	require.NoError(t, TestApp.DB.Where("save_id = ?", saveUUID).First(&saveRec).Error)
	require.Equal(t, dbName, saveRec.DBName)
	require.Equal(t, "postgres", saveRec.Type)

	// Print debug info for what we are searching for
	fmt.Printf("Test is searching for save_id: '%v'\n", backupResp.SaveID)

	// List all GridFS files and their metadata for debugging
	files, err := mongoClient.Database(dbName).Collection("fs.files").Find(context.Background(), bson.M{})
	require.NoError(t, err)
	fmt.Println("GridFS files and their metadata.save_id values:")
	for files.Next(context.Background()) {
		var fileDoc bson.M
		require.NoError(t, files.Decode(&fileDoc))
		meta, _ := fileDoc["metadata"].(bson.M)
		fmt.Printf("  _id=%v  metadata=%+v\n", fileDoc["_id"], meta)
	}
	require.NoError(t, files.Err())

	// Now try the actual filter as before
	filter := bson.M{"metadata.save_id": backupResp.SaveID}
	cursor, err := mongoClient.Database(dbName).Collection("fs.files").Find(context.Background(), filter)
	require.NoError(t, err)
	defer cursor.Close(context.Background())
	require.True(t, cursor.Next(context.Background()), "No GridFS file found with metadata.save_id")

	var fileDoc bson.M
	require.NoError(t, cursor.Decode(&fileDoc))
	fileID := fileDoc["_id"]

	var buf bytes.Buffer
	gfs, err := gridfs.NewBucket(mongoClient.Database(dbName))
	require.NoError(t, err)
	dlStream, err := gfs.OpenDownloadStream(fileID)
	require.NoError(t, err)
	_, err = io.Copy(&buf, dlStream)
	require.NoError(t, err)
	dlStream.Close()

	// Use direct relative path for the fixture file
	fixturePath := filepath.Join("tests", "testutils", "fixtures", "reviews.dump")
	fixture, err := os.ReadFile(fixturePath)
	require.NoError(t, err)
	require.Equal(t, fixture, buf.Bytes(), "GridFS backup does not match fixture")
}

//func TestBackupPostgres_HappyPath(t *testing.T) {
//	testutils.ResetPostgresDB(t, TestApp)
//	testutils.ResetMongoDB(t, TestApp)
//
//	// The db_name to use for the test and for MongoDB checks
//	dbName := "poptape_reviews"
//
//	// Setup MongoDB test client and drop test DB to start clean
//	mongoClient := testutils.TestMongoClient(t)
//	defer mongoClient.Disconnect(context.Background())
//	err := mongoClient.Database(dbName).Drop(context.Background())
//	require.NoError(t, err)
//
//	superUser := os.Getenv("SUPERUSER")
//	superPass := os.Getenv("SUPERPASS")
//	require.NotEmpty(t, superUser)
//	require.NotEmpty(t, superPass)
//	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)
//
//	// Create reviews cred via API
//	payload := map[string]interface{}{
//		"db_name":     dbName,
//		"type":        "postgres",
//		"url":         "/reviews",
//		"db_username": "poptape_reviews",
//		"db_password": base64.StdEncoding.EncodeToString([]byte("password")),
//		"db_port":     "5432",
//		"host":        "poptape-reviews-db-1",
//		"role_name":   "reviews",
//		"ms_name":     "reviews",
//	}
//	body, _ := json.Marshal(payload)
//	req, _ := http.NewRequest("POST", "/admin/creds", bytes.NewReader(body))
//	req.Header.Set("y-access-token", token)
//	req.Header.Set("Content-Type", "application/json")
//	w := httptest.NewRecorder()
//	TestApp.Router.ServeHTTP(w, req)
//	require.Equal(t, http.StatusCreated, w.Code)
//	var resp struct{ Message string }
//	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
//
//	// Get microservice_id for "reviews" from API
//	reqMS, _ := http.NewRequest("GET", "/admin/microservices", nil)
//	reqMS.Header.Set("y-access-token", token)
//	wMS := httptest.NewRecorder()
//	TestApp.Router.ServeHTTP(wMS, reqMS)
//	require.Equal(t, http.StatusOK, wMS.Code)
//	var msResp struct {
//		Microservices []struct {
//			MicroserviceId string `json:"microservice_id"`
//			MSName         string `json:"ms_name"`
//			CreatedBy      string `json:"created_by"`
//			Created        string `json:"created"`
//		} `json:"microservices"`
//	}
//	require.NoError(t, json.Unmarshal(wMS.Body.Bytes(), &msResp))
//	var msID string
//	for _, ms := range msResp.Microservices {
//		if ms.MSName == "reviews" {
//			msID = ms.MicroserviceId
//			break
//		}
//	}
//	require.NotEmpty(t, msID, "could not find microservice_id for reviews")
//
//	// Mock CommandRunner for pg_dump with the correct fixture for postgres
//	TestApp.CommandRunner = &testutils.MockCommandRunner{
//		T: t,
//		Fixtures: map[string]string{
//			"pg_dump": "reviews.dump", // must be in testutils/fixtures/
//		},
//	}
//
//	// Call the backup endpoint
//	url := fmt.Sprintf("/admin/save/%s/%s?mode=all", msID, dbName)
//	req2, _ := http.NewRequest("GET", url, nil)
//	req2.Header.Set("y-access-token", token)
//	w2 := httptest.NewRecorder()
//	TestApp.Router.ServeHTTP(w2, req2)
//	require.Equal(t, http.StatusCreated, w2.Code)
//
//	var backupResp struct {
//		Message   string `json:"message"`
//		NoOfBytes int64  `json:"no_of_bytes"`
//		SaveID    string `json:"save_id"`
//	}
//	require.NoError(t, json.Unmarshal(w2.Body.Bytes(), &backupResp))
//	require.Contains(t, backupResp.Message, "postgres db saved")
//	require.NotZero(t, backupResp.NoOfBytes)
//	require.NotEmpty(t, backupResp.SaveID)
//
//	// Check save record exists in saverecords table
//	var saveRec app.SaveRecord
//	saveUUID, err := uuid.Parse(backupResp.SaveID)
//	require.NoError(t, err)
//	require.NoError(t, TestApp.DB.Where("save_id = ?", saveUUID).First(&saveRec).Error)
//	require.Equal(t, dbName, saveRec.DBName)
//	require.Equal(t, "postgres", saveRec.Type)
//
//	// Print debug info for what we are searching for
//	fmt.Printf("Test is searching for save_id: '%v'\n", backupResp.SaveID)
//
//	// List all GridFS files and their metadata for debugging
//	files, err := mongoClient.Database(dbName).Collection("fs.files").Find(context.Background(), bson.M{})
//	require.NoError(t, err)
//	fmt.Println("GridFS files and their metadata.save_id values:")
//	for files.Next(context.Background()) {
//		var fileDoc bson.M
//		require.NoError(t, files.Decode(&fileDoc))
//		meta, _ := fileDoc["metadata"].(bson.M)
//		fmt.Printf("  _id=%v  metadata=%+v\n", fileDoc["_id"], meta)
//	}
//	require.NoError(t, files.Err())
//
//	// Now try the actual filter as before
//	filter := bson.M{"metadata.save_id": backupResp.SaveID}
//	cursor, err := mongoClient.Database(dbName).Collection("fs.files").Find(context.Background(), filter)
//	require.NoError(t, err)
//	defer cursor.Close(context.Background())
//	require.True(t, cursor.Next(context.Background()), "No GridFS file found with metadata.save_id")
//
//	var fileDoc bson.M
//	require.NoError(t, cursor.Decode(&fileDoc))
//	fileID := fileDoc["_id"]
//
//	var buf bytes.Buffer
//	gfs, err := gridfs.NewBucket(mongoClient.Database(dbName))
//	require.NoError(t, err)
//	dlStream, err := gfs.OpenDownloadStream(fileID)
//	require.NoError(t, err)
//	_, err = io.Copy(&buf, dlStream)
//	require.NoError(t, err)
//	dlStream.Close()
//
//	// Always resolve the fixture path from the repo root: testutils/fixtures/reviews.dump
//	_, thisFile, _, ok := runtime.Caller(0)
//	if !ok {
//		t.Fatalf("unable to determine caller for fixture path")
//	}
//	testsDir := filepath.Dir(thisFile)
//	rootDir := filepath.Dir(testsDir)
//	fixturePath := filepath.Join(rootDir, "testutils", "fixtures", "reviews.dump")
//	fixture, err := os.ReadFile(fixturePath)
//	require.NoError(t, err)
//	require.Equal(t, fixture, buf.Bytes(), "GridFS backup does not match fixture")
//}
//
//func TestBackupPostgres_FailBadMSInURL(t *testing.T) {
//	testutils.ResetPostgresDB(t, TestApp)
//
//	superUser := os.Getenv("SUPERUSER")
//	superPass := os.Getenv("SUPERPASS")
//	require.NotEmpty(t, superUser)
//	require.NotEmpty(t, superPass)
//	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)
//
//	// Call the backup endpoint
//	url := fmt.Sprintf("/admin/save/%s/%s?mode=all", "garbageMS", "poptape_reviews")
//	req2, _ := http.NewRequest("GET", url, nil)
//	req2.Header.Set("y-access-token", token)
//	w2 := httptest.NewRecorder()
//	TestApp.Router.ServeHTTP(w2, req2)
//	require.Equal(t, http.StatusBadRequest, w2.Code)
//	require.Contains(t, w2.Body.String(), "Bad request [ms]")
//}

func TestBackupPostgres_FailBadJWTGen(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	testutils.ResetMongoDB(t, TestApp)

	// The db_name to use for the test and for MongoDB checks
	dbName := "poptape_reviews"

	// Setup MongoDB test client and drop test DB to start clean
	mongoClient := testutils.TestMongoClient(t)
	defer mongoClient.Disconnect(context.Background())
	err := mongoClient.Database(dbName).Drop(context.Background())
	require.NoError(t, err)

	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	// Create reviews cred via API
	payload := map[string]interface{}{
		"db_name":     dbName,
		"type":        "postgres",
		"url":         "/reviews",
		"db_username": "poptape_reviews",
		"db_password": base64.StdEncoding.EncodeToString([]byte("password")),
		"db_port":     "5432",
		"host":        "poptape-reviews-db-1",
		"role_name":   "reviews",
		"ms_name":     "reviews",
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "/admin/creds", bytes.NewReader(body))
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)
	var resp struct{ Message string }
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	// Get microservice_id for "reviews" from API
	reqMS, _ := http.NewRequest("GET", "/admin/microservices", nil)
	reqMS.Header.Set("y-access-token", token)
	wMS := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(wMS, reqMS)
	require.Equal(t, http.StatusOK, wMS.Code)
	var msResp struct {
		Microservices []struct {
			MicroserviceId string `json:"microservice_id"`
			MSName         string `json:"ms_name"`
			CreatedBy      string `json:"created_by"`
			Created        string `json:"created"`
		} `json:"microservices"`
	}
	require.NoError(t, json.Unmarshal(wMS.Body.Bytes(), &msResp))
	var msID string
	for _, ms := range msResp.Microservices {
		if ms.MSName == "reviews" {
			msID = ms.MicroserviceId
			break
		}
	}
	require.NotEmpty(t, msID, "could not find microservice_id for reviews")

	// save original function
	orig := utils.GenerateToken
	defer func() { utils.GenerateToken = orig }()

	// mock GenerateToken
	utils.GenerateToken = func(username string, adminId uuid.UUID) (string, error) {
		return "", errors.New("JWT error")
	}

	// Call the backup endpoint
	url := fmt.Sprintf("/admin/save/%s/%s?mode=all", msID, dbName)
	req2, _ := http.NewRequest("GET", url, nil)
	req2.Header.Set("y-access-token", token)
	w2 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w2, req2)
	require.Equal(t, http.StatusInternalServerError, w2.Code)
	require.Contains(t, w2.Body.String(), "Something went bang")

}
