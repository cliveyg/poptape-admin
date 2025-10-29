package testutils

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
)

// AssertMongoGridFSDeleted asserts that no GridFS file exists with the given saveId in the provided database.
// Fails the test if any file is found.
func AssertMongoGridFSDeleted(t *testing.T, dbName string, saveId string) {
	mongoClient := TestMongoClient(t)
	defer mongoClient.Disconnect(context.Background())
	filter := bson.M{"metadata.save_id": saveId}
	files, err := mongoClient.Database(dbName).Collection("fs.files").Find(context.Background(), filter)
	require.NoError(t, err)
	require.False(t, files.Next(context.Background()), "GridFS should have no file for save_id=%s", saveId)
}
