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
