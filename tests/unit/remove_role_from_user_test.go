package unit

import (
	"errors"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func TestRemoveRoleFromUser_HappyPathSQLite(t *testing.T) {
	a, db := testutils.SetupTestAppWithSQLite()
	roleName := "adminrole"
	testutils.CreateTestRole(t, db, roleName)
	user := testutils.CreateTestUserWithRole(t, db, "user_happy", roleName)

	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	testutils.SetGinParams(c, user.AdminId.String(), roleName)

	a.RemoveRoleFromUser(c)

	assert.Equal(t, http.StatusGone, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Contains(t, resp["message"], roleName)
	assert.Contains(t, resp["message"], user.AdminId.String())

	// Verify user no longer has the role
	var updatedUser app.User
	err := db.Preload("Roles").First(&updatedUser, "admin_id = ?", user.AdminId).Error
	assert.NoError(t, err)
	for _, r := range updatedUser.Roles {
		assert.NotEqual(t, roleName, r.Name, "Role should have been removed")
	}
}

func TestRemoveRoleFromUser_GetRoleDetailsError(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	user := testutils.CreateTestUserBasic("user_getroledetailserr")
	c, w := testutils.CreateGinContextWithUser(user)
	testutils.SetGinParams(c, user.AdminId.String(), "admin")
	mock.ExpectQuery(`SELECT \* FROM "users" WHERE "users"."deleted" IS NULL AND "users"."admin_id" = .+`).WillReturnError(errors.New("bad request"))
	a.RemoveRoleFromUser(c)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, "Bad request", resp["message"])
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRemoveRoleFromUser_RoleNotPresent(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	user := testutils.CreateTestUserBasic("user_norole")
	c, w := testutils.CreateGinContextWithUser(user)
	testutils.SetGinParams(c, user.AdminId.String(), "ghost")
	// 1. users query FIRST
	mock.ExpectQuery(`SELECT \* FROM "users" WHERE "users"."deleted" IS NULL AND "users"."admin_id" = \$1`).WithArgs(user.AdminId).
		WillReturnRows(sqlmock.NewRows([]string{"admin_id", "username", "active", "validated"}).
			AddRow(user.AdminId, user.Username, true, true),
		)
	// 2. user_role query
	mock.ExpectQuery(`SELECT \* FROM "user_role" WHERE "user_role"."user_admin_id" = \$1`).WithArgs(user.AdminId).
		WillReturnRows(sqlmock.NewRows([]string{"user_admin_id", "role_name"}))
	// No expectation for roles table query (handler does not query roles if user has no matching role)
	a.RemoveRoleFromUser(c)
	assert.Equal(t, http.StatusNotModified, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRemoveRoleFromUser_RoleNotExistInDB(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	roleName := "ghost"
	user := app.User{
		AdminId:   uuid.New(),
		Username:  "user_role_not_in_db",
		Active:    true,
		Validated: true,
		Roles:     []app.Role{{Name: roleName}},
	}
	c, w := testutils.CreateGinContextWithUser(user)
	testutils.SetGinParams(c, user.AdminId.String(), roleName)
	// 1. users query FIRST
	mock.ExpectQuery(`SELECT \* FROM "users" WHERE "users"."deleted" IS NULL AND "users"."admin_id" = \$1`).WithArgs(user.AdminId).
		WillReturnRows(sqlmock.NewRows([]string{"admin_id", "username", "active", "validated"}).
			AddRow(user.AdminId, user.Username, true, true),
		)
	// 2. user_role query
	mock.ExpectQuery(`SELECT \* FROM "user_role" WHERE "user_role"."user_admin_id" = \$1`).WithArgs(user.AdminId).
		WillReturnRows(sqlmock.NewRows([]string{"user_admin_id", "role_name"}).AddRow(user.AdminId, roleName))
	// 3. roles join for preload
	mock.ExpectQuery(`SELECT \* FROM "roles"`).
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow(roleName))
	// 4. Role lookup fails
	mock.ExpectQuery(`SELECT \* FROM "roles" WHERE "roles"."name" = \$1 ORDER BY "roles"."name" LIMIT \$2`).WithArgs(roleName, 1).
		WillReturnError(errors.New("role does not exist"))
	a.RemoveRoleFromUser(c)
	assert.Equal(t, http.StatusNotFound, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, "Role does not exist", resp["message"])
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRemoveRoleFromUser_AssociationClearFails(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	roleName := "admin"
	user := app.User{
		AdminId:   uuid.New(),
		Username:  "user_assocfail",
		Active:    true,
		Validated: true,
		Roles:     []app.Role{{Name: roleName}},
	}
	c, w := testutils.CreateGinContextWithUser(user)
	testutils.SetGinParams(c, user.AdminId.String(), roleName)
	// 1. users query FIRST
	mock.ExpectQuery(`SELECT \* FROM "users" WHERE "users"."deleted" IS NULL AND "users"."admin_id" = \$1`).WithArgs(user.AdminId).
		WillReturnRows(sqlmock.NewRows([]string{"admin_id", "username", "active", "validated"}).
			AddRow(user.AdminId, user.Username, true, true),
		)
	// 2. user_role query
	mock.ExpectQuery(`SELECT \* FROM "user_role" WHERE "user_role"."user_admin_id" = \$1`).WithArgs(user.AdminId).
		WillReturnRows(sqlmock.NewRows([]string{"user_admin_id", "role_name"}).AddRow(user.AdminId, roleName))
	// 3. roles join for preload
	mock.ExpectQuery(`SELECT \* FROM "roles"`).
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow(roleName))
	// 4. Role lookup succeeds
	mock.ExpectQuery(`SELECT \* FROM "roles" WHERE "roles"."name" = \$1 ORDER BY "roles"."name" LIMIT \$2`).WithArgs(roleName, 1).
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow(roleName))
	// 5. Association clear fails
	mock.ExpectBegin()
	mock.ExpectExec(`DELETE FROM "user_role" WHERE "user_role"."user_admin_id" = \$1`).WithArgs(user.AdminId).
		WillReturnError(errors.New("forced clear error"))
	mock.ExpectRollback()
	a.RemoveRoleFromUser(c)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, "Something went bang [3]", resp["message"])
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRemoveRoleFromUser_SaveFails(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	roleName := "admin"
	user := app.User{
		AdminId:   uuid.New(),
		Username:  "user_savefail",
		Active:    true,
		Validated: true,
		Roles:     []app.Role{{Name: roleName}},
	}
	c, w := testutils.CreateGinContextWithUser(user)
	testutils.SetGinParams(c, user.AdminId.String(), roleName)

	// Match the logs exactly:
	mock.ExpectQuery(`SELECT \* FROM "users" WHERE "users"."deleted" IS NULL AND "users"."admin_id" = \$1`).
		WithArgs(user.AdminId).
		WillReturnRows(sqlmock.NewRows([]string{"admin_id", "username", "active", "validated"}).
			AddRow(user.AdminId, user.Username, true, true))
	mock.ExpectQuery(`SELECT \* FROM "user_role" WHERE "user_role"."user_admin_id" = \$1`).
		WithArgs(user.AdminId).
		WillReturnRows(sqlmock.NewRows([]string{"user_admin_id", "role_name"}).
			AddRow(user.AdminId, roleName))
	mock.ExpectQuery(`SELECT \* FROM "roles"`).
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow(roleName))
	mock.ExpectQuery(`SELECT \* FROM "roles" WHERE "roles"."name" = \$1 ORDER BY "roles"."name" LIMIT \$2`).
		WithArgs(roleName, 1).
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow(roleName))
	mock.ExpectBegin()
	// Simulate failure of association clear by returning an error on DELETE
	mock.ExpectExec(`DELETE FROM "user_role" WHERE "user_role"."user_admin_id" = \$1`).
		WithArgs(user.AdminId).
		WillReturnError(errors.New("forced clear error"))
	mock.ExpectRollback()

	a.RemoveRoleFromUser(c)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, "Something went bang [3]", resp["message"])
	assert.NoError(t, mock.ExpectationsWereMet())
}
