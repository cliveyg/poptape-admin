package unit

import (
	"github.com/cliveyg/poptape-admin/testutils"
	"testing"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestGetUUIDFromParams_Success(t *testing.T) {
	c, _ := gin.CreateTestContext(nil)

	expected := uuid.New()
	c.Set("user_id", expected.String())

	var actual uuid.UUID
	logger := testutils.CreateTestLogger()
	a := &app.App{Log: logger}

	err := a.GetUUIDFromParams(c, &actual, "user_id")
	require.NoError(t, err)
	require.Equal(t, expected, actual)
}

func TestGetUUIDFromParams_MissingKey(t *testing.T) {
	c, _ := gin.CreateTestContext(nil)

	var actual uuid.UUID
	logger := testutils.CreateTestLogger()
	a := &app.App{Log: logger}

	err := a.GetUUIDFromParams(c, &actual, "user_id")
	require.Error(t, err)
	require.Equal(t, "key is missing", err.Error())
}

func TestGetUUIDFromParams_InvalidUUID(t *testing.T) {
	c, _ := gin.CreateTestContext(nil)

	c.Set("user_id", "not-a-valid-uuid")

	var actual uuid.UUID
	logger := testutils.CreateTestLogger()
	a := &app.App{Log: logger}

	err := a.GetUUIDFromParams(c, &actual, "user_id")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid UUID")
}

func TestGetUUIDFromParams_ValueIsNotString(t *testing.T) {
	c, _ := gin.CreateTestContext(nil)

	c.Set("user_id", 123456)

	var actual uuid.UUID
	logger := testutils.CreateTestLogger()
	a := &app.App{Log: logger}

	err := a.GetUUIDFromParams(c, &actual, "user_id")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid UUID")
}
