package testutils

import (
	"context"
	"fmt"
	"os"
	"strings"
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

func DropTestMongoDatabases(t *testing.T, client *mongo.Client, msPrefix string) {
	ctx := context.Background()
	dbs, err := client.ListDatabaseNames(ctx, map[string]interface{}{})
	if err != nil {
		t.Fatalf("Failed to list mongo dbs: %v", err)
	}
	for _, db := range dbs {
		if strings.HasPrefix(db, msPrefix) {
			if err := client.Database(db).Drop(ctx); err != nil {
				t.Errorf("Failed to drop test db %s: %v", db, err)
			}
		}
	}
}
