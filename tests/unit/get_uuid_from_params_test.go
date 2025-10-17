package unit

import (
	"testing"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestGetUUIDFromParams_Success(t *testing.T) {
	c, _ := gin.CreateTestContext(nil)

	// Simulate setting a valid UUID in Gin context
	expected := uuid.New()
	c.Set("user_id", expected.String())

	var actual uuid.UUID
	a := &app.App{}

	err := a.GetUUIDFromParams(c, &actual, "user_id")
	require.NoError(t, err)
	require.Equal(t, expected, actual)
}

func TestGetUUIDFromParams_MissingKey(t *testing.T) {
	c, _ := gin.CreateTestContext(nil)

	// Do not set "user_id" key
	var actual uuid.UUID
	a := &app.App{}

	err := a.GetUUIDFromParams(c, &actual, "user_id")
	require.Error(t, err)
	require.Equal(t, "key is missing", err.Error())
}

func TestGetUUIDFromParams_InvalidUUID(t *testing.T) {
	c, _ := gin.CreateTestContext(nil)

	// Set an invalid UUID string
	c.Set("user_id", "not-a-valid-uuid")

	var actual uuid.UUID
	a := &app.App{}

	err := a.GetUUIDFromParams(c, &actual, "user_id")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid UUID")
}

func TestGetUUIDFromParams_ValueIsNotString(t *testing.T) {
	c, _ := gin.CreateTestContext(nil)

	// Set a value that is not a string, e.g. an int
	c.Set("user_id", 123456)

	var actual uuid.UUID
	a := &app.App{}

	err := a.GetUUIDFromParams(c, &actual, "user_id")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid UUID")
}
