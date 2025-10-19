package unit

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// PASSING: Happy Path
func TestFetchUser_HappyPath(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	userID := uuid.New().String()

	// 1. users table
	mock.ExpectQuery(`SELECT \* FROM "users" WHERE "users"\."deleted" IS NULL AND "users"\."admin_id" = \$1`).
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{
			"admin_id", "username", "password", "last_login", "active", "validated", "created", "updated",
		}).AddRow(userID, "testuser", []byte("irrelevant"), nil, true, true, nil, nil))

	// 2. user_role join table
	mock.ExpectQuery(`SELECT \* FROM "user_role" WHERE "user_role"\."user_admin_id" = \$1`).
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{"user_admin_id", "role_name"}).AddRow(userID, "admin"))

	// 3. roles table
	mock.ExpectQuery(`SELECT \* FROM "roles" WHERE "roles"\."name" = \$1`).
		WithArgs("admin").
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("admin"))

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{gin.Param{Key: "aId", Value: userID}}

	a.FetchUser(c)

	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), "testuser")
	require.Contains(t, w.Body.String(), "admin")
	require.NoError(t, mock.ExpectationsWereMet())
}

// PASSING: Not Found (only user_role and users queries happen, roles not needed)
func TestFetchUser_NotFound(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	userID := uuid.New().String()

	// 1. users table - no user
	mock.ExpectQuery(`SELECT \* FROM "users" WHERE "users"\."deleted" IS NULL AND "users"\."admin_id" = \$1`).
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{
			"admin_id", "username", "password", "last_login", "active", "validated", "created", "updated",
		}))

	// 2. user_role join table - no roles
	mock.ExpectQuery(`SELECT \* FROM "user_role" WHERE "user_role"\."user_admin_id" = \$1`).
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{"user_admin_id", "role_name"}))

	// 3. roles table -- DO NOT MOCK THIS, GORM doesn't query roles if user_role returns no rows

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{gin.Param{Key: "aId", Value: userID}}

	a.FetchUser(c)

	require.Equal(t, http.StatusNotFound, w.Code)
	require.Contains(t, w.Body.String(), "User not found")
	require.NoError(t, mock.ExpectationsWereMet())
}

// PASSING: Bad UUID (no DB queries)
func TestFetchUser_BadUUID(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{gin.Param{Key: "aId", Value: "not-a-uuid"}}

	a.FetchUser(c)

	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "Bad request")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestFetchUser_DBError(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	userID := uuid.New().String()

	// EXACT SQL and args from your logs
	mock.ExpectQuery(`SELECT \* FROM "users" WHERE "users"\."deleted" IS NULL AND "users"\."admin_id" = \$1`).
		WithArgs(userID).
		WillReturnError(errors.New("db failure"))

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{gin.Param{Key: "aId", Value: userID}}
	a.FetchUser(c)
	require.Equal(t, http.StatusInternalServerError, w.Code)
	require.Contains(t, w.Body.String(), "Something went pop")
	require.NoError(t, mock.ExpectationsWereMet())
}
