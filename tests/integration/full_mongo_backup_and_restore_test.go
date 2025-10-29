package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestFullMongoBackupAndRestore_HappyPath(t *testing.T) {
	// --- Step 1: Create creds record via API ---
	testutils.ResetPostgresDB(t, TestApp) // Clean slate in system DB

	// Use docker service name and internal port for CI network!
	mongoHost := "mongo-test"
	mongoPort := "27017"
	mongoDB := "poptape_fotos"
	mongoUser := "poptape_fotos"
	mongoPass := "6743929283749d932"

	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	payload := map[string]interface{}{
		"db_name":     mongoDB,
		"type":        "mongo",
		"url":         "/fotos",
		"db_username": mongoUser,
		"db_password": base64.StdEncoding.EncodeToString([]byte(mongoPass)),
		"db_port":     mongoPort,
		"host":        mongoHost,
		"role_name":   "fotos",
		"ms_name":     "fotos",
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

	// --- Step 2: Seed the mongo-test DB with some data ---
	// Connect directly to mongo-test (not via app)
	mongoURI := fmt.Sprintf("mongodb://%s:%s@%s:%s/%s?authSource=admin",
		mongoUser, mongoPass, mongoHost, mongoPort, mongoDB)
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(mongoURI))
	require.NoError(t, err)
	defer client.Disconnect(context.Background())

	coll := client.Database(mongoDB).Collection("animals")
	docs := []interface{}{
		bson.M{"name": "Lion", "type": "Mammal"},
		bson.M{"name": "Parrot", "type": "Bird"},
	}
	_, err = coll.InsertMany(context.Background(), docs)
	require.NoError(t, err)

	// --- Step 3: Backup the DB via API ---
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
		if ms.MSName == "fotos" {
			msID = ms.MicroserviceId
			break
		}
	}
	require.NotEmpty(t, msID)

	backupURL := fmt.Sprintf("/admin/save/%s/%s?mode=all", msID, mongoDB)
	reqBackup, _ := http.NewRequest("GET", backupURL, nil)
	reqBackup.Header.Set("y-access-token", token)
	wBackup := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(wBackup, reqBackup)
	require.Equal(t, http.StatusCreated, wBackup.Code)
	var backupResp struct {
		Message   string `json:"message"`
		NoOfBytes int64  `json:"no_of_bytes"`
		SaveID    string `json:"save_id"`
	}
	require.NoError(t, json.Unmarshal(wBackup.Body.Bytes(), &backupResp))
	require.NotEmpty(t, backupResp.SaveID)
	require.Contains(t, backupResp.Message, "mongo db saved")

	// --- Step 4: Remove all records (simulate a disaster) ---
	err = coll.Drop(context.Background())
	require.NoError(t, err)
	count, err := coll.CountDocuments(context.Background(), bson.M{})
	require.NoError(t, err)
	require.Equal(t, int64(0), count, "Collection should be empty after drop")

	// --- Step 5: Restore the DB via API ---
	restoreURL := "/admin/load/data/" + backupResp.SaveID
	reqRestore, _ := http.NewRequest("GET", restoreURL, nil)
	reqRestore.Header.Set("y-access-token", token)
	wRestore := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(wRestore, reqRestore)
	require.Equal(t, http.StatusOK, wRestore.Code)
	var restoreResp map[string]interface{}
	require.NoError(t, json.Unmarshal(wRestore.Body.Bytes(), &restoreResp))
	require.Contains(t, restoreResp["message"].(string), "Mongo restore succeeded")

	// --- Step 6: Assert records are restored ---
	cursor, err := coll.Find(context.Background(), bson.M{})
	require.NoError(t, err)
	var results []bson.M
	require.NoError(t, cursor.All(context.Background(), &results))
	require.Len(t, results, 2)
	names := []string{results[0]["name"].(string), results[1]["name"].(string)}
	require.Contains(t, names, "Lion")
	require.Contains(t, names, "Parrot")
}
