package unit

import (
	"errors"
	"github.com/stretchr/testify/mock"
	"net/http"
	"os"
	"testing"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestFetchCredsById_InvalidUUID(t *testing.T) {
	a, _ := testutils.SetupTestAppWithSQLite()
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	c.Params = gin.Params{{Key: "cId", Value: "not-a-uuid"}}

	a.FetchCredsById(c)
	require.Equal(t, http.StatusBadRequest, w.Code)
	out := testutils.ExtractJSONResponse(t, w)
	require.Equal(t, "Bad request", out["message"])
}

func TestFetchCredsById_CredNotFound(t *testing.T) {
	a, _ := testutils.SetupTestAppWithSQLite()
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	// Use a valid UUID that does not exist
	missingId := uuid.New().String()
	c.Params = gin.Params{{Key: "cId", Value: missingId}}

	a.FetchCredsById(c)
	require.Equal(t, http.StatusNotFound, w.Code)
	out := testutils.ExtractJSONResponse(t, w)
	require.Equal(t, "Creds not found", out["message"])
}

func TestFetchCredsById_DBError(t *testing.T) {
	// Use MockDB to simulate DB error
	mockDB := &testutils.MockDB{}
	logger := testutils.CreateTestLogger()
	a := &app.App{
		DB:  mockDB,
		Log: logger,
	}
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	validId := uuid.New()
	c.Params = gin.Params{{Key: "cId", Value: validId.String()}}

	// Simulate DB error other than ErrRecordNotFound
	dbErr := errors.New("database connection failed")
	gdb := &gorm.DB{Error: dbErr}
	mockDB.On("First", &app.Cred{CredId: validId}, mock.Anything).Return(gdb)

	a.FetchCredsById(c)
	require.Equal(t, http.StatusInternalServerError, w.Code)
	out := testutils.ExtractJSONResponse(t, w)
	require.Equal(t, "Something went neee", out["message"])
}

func TestFetchCredsById_HappyPath(t *testing.T) {
	a, db := testutils.SetupTestAppWithSQLite()
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)

	ssn := os.Getenv("SUPERSECRETNONCE")
	os.Setenv("SUPERSECRETNONCE", "supersecret1")
	defer os.Setenv("SUPERSECRETNONCE", ssn)

	ssk := os.Getenv("SUPERSECRETKEY")
	os.Setenv("SUPERSECRETKEY", "supersecretkey123456789012345678")
	defer os.Setenv("SUPERSECRETKEY", ssk)

	// Insert test Cred
	testCred, err := testutils.CreateTestCred(db)
	require.NoError(t, err)
	cid := testCred.CredId.String()
	c.Params = gin.Params{{Key: "cId", Value: cid}}

	a.FetchCredsById(c)
	require.Equal(t, http.StatusOK, w.Code)
	out := testutils.ExtractJSONResponse(t, w)
	creds, ok := out["creds"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, "XXXXX", creds["db_password"])
	require.Equal(t, testCred.CredId.String(), creds["cred_id"])
}
