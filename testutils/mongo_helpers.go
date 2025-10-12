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
	uri := fmt.Sprintf(
		"mongodb://%s:%s@%s:%s",
		os.Getenv("MONGO_USERNAME"),
		os.Getenv("MONGO_PASSWORD"),
		os.Getenv("MONGO_HOST"),
		os.Getenv("MONGO_PORT"),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
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
