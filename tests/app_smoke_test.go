package tests

import (
	"context"
	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	a := &app.App{}
	a.InitialisePostgres()
	a.PopulatePostgresDB()
	a.InitialiseMongo()
	// ... any other setup
	code := m.Run()
	os.Exit(code)
}

func TestHarnessSmokeTest(t *testing.T) {
	msName := testutils.TestMicroserviceName(1) // "test_microservice1"

	// MongoDB: Create dummy collection in test db, then drop it
	client := testutils.TestMongoClient(t)
	defer func() { _ = client.Disconnect(context.Background()) }()
	db := client.Database(msName)
	if err := db.CreateCollection(context.Background(), "fs.files"); err != nil {
		t.Fatalf("Failed to create dummy collection: %v", err)
	}
	testutils.DropTestMongoDatabases(t, client, "test_microservice")

	// Postgres: Create and drop test microservice
	dbpg := testutils.TestPostgresDB(t)
	testutils.CreateTestMicroservice(t, dbpg, msName)
	testutils.DropTestMicroservicesByPrefix(t, dbpg, "test_microservice")
}
