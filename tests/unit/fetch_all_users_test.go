package unit

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchAllUsers_HappyPath(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	user1ID := uuid.New()
	user2ID := uuid.New()
	now := time.Now()

	// Mock users query
	userRows := sqlmock.NewRows([]string{
		"admin_id", "username", "password", "last_login", "active", "validated", "created", "updated", "deleted",
	}).
		AddRow(user1ID, "alice", []byte("pw1"), now, true, true, now, now, nil).
		AddRow(user2ID, "bob", []byte("pw2"), now, true, true, now, now, nil)
	mock.ExpectQuery(`SELECT \* FROM "users" WHERE "users"\."deleted" IS NULL`).
		WillReturnRows(userRows)

	// Mock user_role join table query for Preload("Roles")
	userRoleRows := sqlmock.NewRows([]string{"user_admin_id", "role_name"}).
		AddRow(user1ID, "admin").
		AddRow(user2ID, "super")
	mock.ExpectQuery(`SELECT \* FROM "user_role" WHERE "user_role"\."user_admin_id" IN \(\$1,\$2\)`).
		WithArgs(user1ID, user2ID).
		WillReturnRows(userRoleRows)

	// Mock roles table query for the loaded role names
	rolesRows := sqlmock.NewRows([]string{"name", "created"}).
		AddRow("admin", now).
		AddRow("super", now)
	mock.ExpectQuery(`SELECT \* FROM "roles" WHERE "roles"\."name" IN \(\$1,\$2\)`).
		WithArgs("admin", "super").
		WillReturnRows(rolesRows)

	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	a.FetchAllUsers(c)

	assert.Equal(t, http.StatusOK, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	users, ok := resp["users"].([]interface{})
	assert.True(t, ok)
	assert.Len(t, users, 2)
	for _, u := range users {
		uMap, ok := u.(map[string]interface{})
		assert.True(t, ok)
		roles, ok := uMap["roles"].([]interface{})
		assert.True(t, ok)
		assert.GreaterOrEqual(t, len(roles), 1)
	}
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestFetchAllUsers_NoUsers(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	userRows := sqlmock.NewRows([]string{
		"admin_id", "username", "password", "last_login", "active", "validated", "created", "updated", "deleted",
	})
	mock.ExpectQuery(`SELECT \* FROM "users" WHERE "users"\."deleted" IS NULL`).WillReturnRows(userRows)

	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	a.FetchAllUsers(c)

	assert.Equal(t, http.StatusOK, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	users, ok := resp["users"].([]interface{})
	assert.True(t, ok)
	assert.Len(t, users, 0)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestFetchAllUsers_DBError(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.ExpectQuery(`SELECT \* FROM "users" WHERE "users"\."deleted" IS NULL`).
		WillReturnError(errors.New("simulated db error"))

	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	a.FetchAllUsers(c)

	require.Equal(t, http.StatusInternalServerError, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	require.Contains(t, resp["message"], "Something went pop")
	require.NoError(t, mock.ExpectationsWereMet())
}
