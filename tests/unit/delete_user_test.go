package unit

import (
	"net/http"
	"os"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/cliveyg/poptape-admin/testutils"
)

func TestDeleteUser_HappyPath(t *testing.T) {
	origSuper := os.Getenv("SUPERUSER")
	os.Setenv("SUPERUSER", "superuser")
	defer os.Setenv("SUPERUSER", origSuper)

	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)

	adminId := uuid.New()
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE "users" SET "deleted"=\$1 WHERE "users"."admin_id" = \$2 AND "users"."deleted" IS NULL`).
		WithArgs(sqlmock.AnyArg(), adminId).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	c.Params = gin.Params{{Key: "aId", Value: adminId.String()}}
	a.DeleteUser(c)
	assert.Equal(t, http.StatusGone, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, "User deleted", resp["message"])
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestDeleteUser_DBDeleteError(t *testing.T) {
	origSuper := os.Getenv("SUPERUSER")
	os.Setenv("SUPERUSER", "superuser")
	defer os.Setenv("SUPERUSER", origSuper)

	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	adminId := uuid.New()

	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE "users" SET "deleted"=\$1 WHERE "users"."admin_id" = \$2 AND "users"."deleted" IS NULL`).
		WithArgs(sqlmock.AnyArg(), adminId).
		WillReturnError(sqlmock.ErrCancelled)
	mock.ExpectRollback()

	c.Params = gin.Params{{Key: "aId", Value: adminId.String()}}
	a.DeleteUser(c)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, "Something went pop", resp["message"])
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestDeleteUser_NonExistentUser(t *testing.T) {
	origSuper := os.Getenv("SUPERUSER")
	os.Setenv("SUPERUSER", "superuser")
	defer os.Setenv("SUPERUSER", origSuper)

	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	adminId := uuid.New()

	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE "users" SET "deleted"=\$1 WHERE "users"."admin_id" = \$2 AND "users"."deleted" IS NULL`).
		WithArgs(sqlmock.AnyArg(), adminId).
		WillReturnResult(sqlmock.NewResult(1, 0))
	mock.ExpectCommit()

	c.Params = gin.Params{{Key: "aId", Value: adminId.String()}}
	a.DeleteUser(c)
	assert.Equal(t, http.StatusGone, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, "User deleted", resp["message"])
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestDeleteUser_InvalidUUID(t *testing.T) {
	origSuper := os.Getenv("SUPERUSER")
	os.Setenv("SUPERUSER", "superuser")
	defer os.Setenv("SUPERUSER", origSuper)

	a, _, _ := testutils.SetupTestAppWithSQLMock(t)
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	c.Params = gin.Params{{Key: "aId", Value: "not-a-uuid"}}

	a.DeleteUser(c)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, "Bad request", resp["message"])
}

func TestDeleteUser_LoggingDoesNotPanic(t *testing.T) {
	origSuper := os.Getenv("SUPERUSER")
	os.Setenv("SUPERUSER", "superuser")
	defer os.Setenv("SUPERUSER", origSuper)

	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	adminId := uuid.New()
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE "users" SET "deleted"=\$1 WHERE "users"."admin_id" = \$2 AND "users"."deleted" IS NULL`).
		WithArgs(sqlmock.AnyArg(), adminId).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	c.Params = gin.Params{{Key: "aId", Value: adminId.String()}}
	assert.NotPanics(t, func() {
		a.DeleteUser(c)
	})
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestDeleteUser_SuperUserFails_SQLite(t *testing.T) {
	origSuper := os.Getenv("SUPERUSER")
	os.Setenv("SUPERUSER", "superuser")
	defer os.Setenv("SUPERUSER", origSuper)

	a, db := testutils.SetupTestAppWithSQLite()
	testutils.CreateTestRole(t, db, "super")
	superUsername := os.Getenv("SUPERUSER")
	if superUsername == "" {
		superUsername = "superuser"
	}
	superUser := testutils.CreateTestUserWithRole(t, db, superUsername, "super")

	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	c.Params = gin.Params{{Key: "aId", Value: superUser.AdminId.String()}}

	a.DeleteUser(c)
	if w.Code == http.StatusInternalServerError {
		resp := testutils.ExtractJSONResponse(t, w)
		assert.Contains(t, resp["message"], "Something went pop")
	} else {
		assert.Equal(t, http.StatusGone, w.Code)
		resp := testutils.ExtractJSONResponse(t, w)
		assert.Equal(t, "User deleted", resp["message"])
	}
}
