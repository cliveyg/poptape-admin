package tests

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/gridfs"
	"net/http"
	"net/http/httptest"
)

func TestBackupPostgres_HappyPath(t *testing.T) {
	resetDB(t, TestApp)

	// Setup MongoDB test client and drop test DB to start clean
	mongoDBName := os.Getenv("MONGO_DBNAME")
	mongoClient := testutils.TestMongoClient(t)
	defer mongoClient.Disconnect(context.Background())
	err := mongoClient.Database(mongoDBName).Drop(context.Background())
	require.NoError(t, err)

	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := loginAndGetToken(t, TestApp, superUser, superPass)

	// Create reviews cred via API
	payload := map[string]interface{}{
		"db_name":     "poptape_reviews",
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

	// Mock CommandRunner for pg_dump
	TestApp.CommandRunner = &mockCommandRunner{t: t}

	// Call the backup endpoint
	url := fmt.Sprintf("/admin/save/%s/poptape_reviews?mode=all", msID)
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
	require.Equal(t, "poptape_reviews", saveRec.DBName)
	require.Equal(t, "postgres", saveRec.Type)

	// Check file saved in MongoDB GridFS by metadata.save_id
	gfs, err := gridfs.NewBucket(mongoClient.Database(mongoDBName))
	require.NoError(t, err)

	filter := bson.M{"metadata.save_id": backupResp.SaveID}
	cursor, err := mongoClient.Database(mongoDBName).Collection("fs.files").Find(context.Background(), filter)
	require.NoError(t, err)
	defer cursor.Close(context.Background())
	require.True(t, cursor.Next(context.Background()), "No GridFS file found with metadata.save_id")
	var fileDoc bson.M
	require.NoError(t, cursor.Decode(&fileDoc))
	fileID := fileDoc["_id"]

	var buf bytes.Buffer
	dlStream, err := gfs.OpenDownloadStream(fileID)
	require.NoError(t, err)
	_, err = io.Copy(&buf, dlStream)
	require.NoError(t, err)
	dlStream.Close()

	fixture, err := os.ReadFile("tests/fixtures/reviews.dump")
	require.NoError(t, err)
	require.Equal(t, fixture, buf.Bytes(), "GridFS backup does not match fixture")
}
