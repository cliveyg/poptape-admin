package unit

import (
	"errors"
	"net/http"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestFetchCredsById_InvalidUUID(t *testing.T) {
	a, _, _ := testutils.SetupTestAppWithSQLMock(t)
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	c.Params = gin.Params{{Key: "cId", Value: "not-a-uuid"}}

	a.FetchCredsById(c)
	require.Equal(t, http.StatusBadRequest, w.Code)
	out := testutils.ExtractJSONResponse(t, w)
	require.Equal(t, "Bad request", out["message"])
}

func TestFetchCredsById_CredNotFound(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	missingID := uuid.New()
	c.Params = gin.Params{{Key: "cId", Value: missingID.String()}}

	mock.ExpectQuery(`SELECT \* FROM "creds" WHERE "creds"\."cred_id" = \$1 ORDER BY "creds"\."cred_id" LIMIT \$2`).
		WithArgs(missingID, 1).
		WillReturnRows(sqlmock.NewRows([]string{
			"cred_id", "db_name", "host", "type", "url", "db_port", "db_username", "db_password", "last_used", "last_used_by", "created_by", "created",
		}))

	a.FetchCredsById(c)
	require.Equal(t, http.StatusNotFound, w.Code)
	out := testutils.ExtractJSONResponse(t, w)
	require.Equal(t, "Creds not found", out["message"])
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestFetchCredsById_DBError(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	validID := uuid.New()
	c.Params = gin.Params{{Key: "cId", Value: validID.String()}}

	mock.ExpectQuery(`SELECT \* FROM "creds" WHERE "creds"\."cred_id" = \$1 ORDER BY "creds"\."cred_id" LIMIT \$2`).
		WithArgs(validID, 1).
		WillReturnError(errors.New("database connection failed"))

	a.FetchCredsById(c)
	require.Equal(t, http.StatusInternalServerError, w.Code)
	out := testutils.ExtractJSONResponse(t, w)
	require.Equal(t, "Something went neee", out["message"])
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestFetchCredsById_HappyPath(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	credID := uuid.New()
	mock.ExpectQuery(`SELECT \* FROM "creds" WHERE "creds"\."cred_id" = \$1 ORDER BY "creds"\."cred_id" LIMIT \$2`).
		WithArgs(credID, 1).
		WillReturnRows(sqlmock.NewRows([]string{
			"cred_id", "db_name", "host", "type", "url", "db_port", "db_username", "db_password", "last_used", "last_used_by", "created_by", "created",
		}).AddRow(credID, "testdb", "localhost", "postgres", "postgres://localhost:5432/testdb", "5432", "admin", "realpass", nil, "tester", uuid.New(), nil))

	c.Params = gin.Params{{Key: "cId", Value: credID.String()}}

	a.FetchCredsById(c)
	require.Equal(t, http.StatusOK, w.Code)
	out := testutils.ExtractJSONResponse(t, w)
	creds, ok := out["creds"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, "XXXXX", creds["db_password"])
	require.Equal(t, credID.String(), creds["cred_id"])
	require.NoError(t, mock.ExpectationsWereMet())
}
