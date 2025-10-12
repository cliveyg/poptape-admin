package integration

import (
	"os"
	"testing"

	"github.com/cliveyg/poptape-admin/testutils"
)

func TestMain(m *testing.M) {
	testutils.LoadEnv(&testing.T{})
	code := m.Run()
	os.Exit(code)
}

func TestHarnessSmokeTest(t *testing.T) {
	msName := testutils.TestMicroserviceName(1) // "test_microservice1"

	// MongoDB: Create dummy collection in test db, then drop it
	client := testutils.TestMongoClient(t)
	defer func() { _ = client.Disconnect(nil) }()
	db := client.Database(msName)
	if err := db.CreateCollection(nil, "fs.files"); err != nil {
		t.Fatalf("Failed to create dummy collection: %v", err)
	}
	testutils.DropTestMongoDatabases(t, client, "test_microservice")

	// Postgres: Create and drop test microservice
	dbpg := testutils.TestPostgresDB(t)
	testutils.CreateTestMicroservice(t, dbpg, msName)
	testutils.DropTestMicroservicesByPrefix(t, dbpg, "test_microservice")
}
