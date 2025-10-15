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
	"time"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/gridfs"
	"go.mongodb.org/mongo-driver/mongo/options"
	"net/http"
	"net/http/httptest"
)

func TestBackupPostgres_HappyPath(t *testing.T) {
	resetDB(t, TestApp)

	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
	}
	mongoDBName := "poptape_reviews"
	resetMongo(t, mongoURI, mongoDBName)

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

	// Check file saved in MongoDB GridFS
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	mongoClient, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	require.NoError(t, err)
	defer mongoClient.Disconnect(ctx)
	gfs, err := gridfs.NewBucket(mongoClient.Database(mongoDBName))
	require.NoError(t, err)

	cursor, err := mongoClient.Database(mongoDBName).Collection("fs.files").Find(ctx, bson.M{})
	require.NoError(t, err)
	defer cursor.Close(ctx)
	require.True(t, cursor.Next(ctx), "No GridFS file found")
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
