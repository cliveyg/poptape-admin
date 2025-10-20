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

func TestAddRoleToUser_GetRoleDetailsError(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	user := testutils.CreateTestUserBasic("user_getroledetailserr")
	c, w := testutils.CreateGinContextWithUser(user)
	testutils.SetGinParams(c, user.AdminId.String(), "admin")
	mock.ExpectQuery(`SELECT \* FROM "users" WHERE "users"."deleted" IS NULL AND "users"."admin_id" = .+`).WillReturnError(errors.New("bad request"))
	a.AddRoleToUser(c)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, "Bad request", resp["message"])
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAddRoleToUser_RoleAlreadyPresent(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	user := testutils.CreateTestUserBasic("user_rolepresent")
	c, w := testutils.CreateGinContextWithUser(user)
	testutils.SetGinParams(c, user.AdminId.String(), "admin")
	// 1. users query FIRST
	mock.ExpectQuery(`SELECT \* FROM "users" WHERE "users"."deleted" IS NULL AND "users"."admin_id" = \$1`).WithArgs(user.AdminId).
		WillReturnRows(sqlmock.NewRows([]string{"admin_id", "username", "active", "validated"}).
			AddRow(user.AdminId, user.Username, true, true),
		)
	// 2. user_role query
	mock.ExpectQuery(`SELECT \* FROM "user_role" WHERE "user_role"."user_admin_id" = \$1`).WithArgs(user.AdminId).
		WillReturnRows(sqlmock.NewRows([]string{"user_admin_id", "role_name"}).
			AddRow(user.AdminId, "admin"),
		)
	// 3. roles join for preload
	mock.ExpectQuery(`SELECT \* FROM "roles"`).
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("admin"))
	a.AddRoleToUser(c)
	assert.Equal(t, http.StatusNotModified, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAddRoleToUser_RoleNotExist(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	user := app.User{
		AdminId:   uuid.New(),
		Username:  "user_norole",
		Active:    true,
		Validated: true,
		Roles:     []app.Role{},
	}
	c, w := testutils.CreateGinContextWithUser(user)
	testutils.SetGinParams(c, user.AdminId.String(), "ghost")
	mock.ExpectQuery(`SELECT \* FROM "users" WHERE "users"."deleted" IS NULL AND "users"."admin_id" = .+`).WillReturnRows(
		sqlmock.NewRows([]string{"admin_id", "username", "active", "validated"}).
			AddRow(user.AdminId, user.Username, true, true),
	)
	mock.ExpectQuery(`SELECT \* FROM "user_role" WHERE "user_role"."user_admin_id" = .+`).WillReturnRows(
		sqlmock.NewRows([]string{"user_admin_id", "role_name"}),
	)
	mock.ExpectQuery(`SELECT \* FROM "roles" WHERE "roles"."name" = \$1 ORDER BY "roles"."name" LIMIT \$2`).WithArgs("ghost", 1).WillReturnError(errors.New("not found"))
	a.AddRoleToUser(c)
	assert.Equal(t, http.StatusNotFound, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, "Role does not exist", resp["message"])
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAddRoleToUser_HappyPathSQLite(t *testing.T) {
	a, db := testutils.SetupTestAppWithSQLite()
	// Create two roles
	testutils.CreateTestRole(t, db, "admin")
	testutils.CreateTestRole(t, db, "aws")

	// Create user with "admin" role
	user := testutils.CreateTestUserWithRole(t, db, "user_happypath", "admin")

	// Prepare Gin context with params: AdminId and "aws" (to add)
	c, w := testutils.CreateGinContextWithUser(user)
	testutils.SetGinParams(c, user.AdminId.String(), "aws")

	// Call handler
	a.AddRoleToUser(c)

	assert.Equal(t, http.StatusCreated, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	expected := "Role [aws] added to user [" + user.AdminId.String() + "]"
	assert.Equal(t, expected, resp["message"])

	// Confirm user now has both roles
	var updatedUser app.User
	err := db.Preload("Roles").First(&updatedUser, "admin_id = ?", user.AdminId).Error
	assert.NoError(t, err)
	assert.ElementsMatch(t, []string{"admin", "aws"}, []string{updatedUser.Roles[0].Name, updatedUser.Roles[1].Name})
}

func TestAddRoleToUser_SaveError(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	user := app.User{
		AdminId:   uuid.New(),
		Username:  "user_saveerr",
		Active:    true,
		Validated: true,
		Roles:     []app.Role{},
	}
	roleName := "admin"
	c, w := testutils.CreateGinContextWithUser(user)
	testutils.SetGinParams(c, user.AdminId.String(), roleName)
	mock.ExpectQuery(`SELECT \* FROM "users" WHERE "users"."deleted" IS NULL AND "users"."admin_id" = .+`).WillReturnRows(
		sqlmock.NewRows([]string{"admin_id", "username", "active", "validated"}).
			AddRow(user.AdminId, user.Username, true, true),
	)
	mock.ExpectQuery(`SELECT \* FROM "user_role" WHERE "user_role"."user_admin_id" = .+`).WillReturnRows(
		sqlmock.NewRows([]string{"user_admin_id", "role_name"}),
	)
	mock.ExpectQuery(`SELECT \* FROM "roles" WHERE "roles"."name" = \$1 ORDER BY "roles"."name" LIMIT \$2`).WithArgs(roleName, 1).WillReturnRows(
		sqlmock.NewRows([]string{"name"}).AddRow(roleName),
	)
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE "users" SET (.+) WHERE "users"."deleted" IS NULL AND "admin_id" = .+`).WillReturnError(errors.New("save failed"))
	mock.ExpectRollback()
	a.AddRoleToUser(c)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Contains(t, resp["message"], "Something went bang")
	assert.NoError(t, mock.ExpectationsWereMet())
}
