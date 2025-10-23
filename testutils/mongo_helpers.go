package testutils

import (
	"context"
	"fmt"
	"github.com/cliveyg/poptape-admin/app"
	"os"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// MongoDB helpers

func TestMongoClient(t *testing.T) *mongo.Client {
	mongoHost := os.Getenv("MONGO_HOST")
	mongoPort := os.Getenv("MONGO_PORT")
	mongoDB := os.Getenv("MONGO_DBNAME")
	mongoUser := os.Getenv("MONGO_USERNAME")
	mongoPass := os.Getenv("MONGO_PASSWORD")

	// Build MongoDB URI
	mongoURI := fmt.Sprintf("mongodb://%s:%s@%s:%s/%s?authSource=admin",
		mongoUser, mongoPass, mongoHost, mongoPort, mongoDB,
	)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	if err != nil {
		t.Fatalf("Failed to connect to mongo: %v", err)
	}
	return client
}

func ResetMongoDB(t *testing.T, a *app.App) {
	ctx := context.Background()
	mongoClient := a.Mongo
	if mongoClient == nil {
		if t != nil {
			t.Fatalf("TestApp.Mongo is nil, cannot reset MongoDB")
		} else {
			panic("TestApp.Mongo is nil, cannot reset MongoDB")
		}
	}
	systemDBs := map[string]bool{
		"admin":  true,
		"local":  true,
		"config": true,
	}

	dbs, err := mongoClient.ListDatabaseNames(ctx, map[string]interface{}{})
	if err != nil {
		if t != nil {
			t.Fatalf("failed to list MongoDB databases: %v", err)
		} else {
			panic(fmt.Sprintf("failed to list MongoDB databases: %v", err))
		}
	}

	for _, dbName := range dbs {
		if !systemDBs[dbName] {
			err := mongoClient.Database(dbName).Drop(ctx)
			if err != nil {
				if t != nil {
					t.Fatalf("failed to drop MongoDB database %s: %v", dbName, err)
				} else {
					panic(fmt.Sprintf("failed to drop MongoDB database %s: %v", dbName, err))
				}
			}
		}
	}
}

func WithMongoEnv(t *testing.T, fn func()) {
	origHost := os.Getenv("MONGO_HOST")
	origPort := os.Getenv("MONGO_PORT")
	origDB := os.Getenv("MONGO_DBNAME")
	origUser := os.Getenv("MONGO_USERNAME")
	origPass := os.Getenv("MONGO_PASSWORD")
	defer func() {
		os.Setenv("MONGO_HOST", origHost)
		os.Setenv("MONGO_PORT", origPort)
		os.Setenv("MONGO_DBNAME", origDB)
		os.Setenv("MONGO_USERNAME", origUser)
		os.Setenv("MONGO_PASSWORD", origPass)
	}()
	os.Setenv("MONGO_HOST", "localhost")
	os.Setenv("MONGO_PORT", "27017")
	os.Setenv("MONGO_DBNAME", "testdb")
	os.Setenv("MONGO_USERNAME", "testuser")
	os.Setenv("MONGO_PASSWORD", "testpass")
	fn()
}
