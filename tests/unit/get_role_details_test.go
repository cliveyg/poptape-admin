package unit

import (
	"errors"
	"net/http"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func TestGetRoleDetails_InvalidAId(t *testing.T) {
	a := &app.App{
		Log: testutils.SetupLogger(),
		DB:  &testutils.MockDB{},
	}
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	testutils.SetGinParams(c, "not-a-uuid", "validrole")
	c.Request, _ = http.NewRequest("GET", "/", nil)
	u := &app.User{}
	rName := new(string)
	err := a.GetRoleDetails(c, u, rName)
	assert.Error(t, err)
	assert.Equal(t, "Invalid aId in url", err.Error())
}

func TestGetRoleDetails_InvalidRoleName(t *testing.T) {
	a := &app.App{
		Log: testutils.SetupLogger(),
		DB:  &testutils.MockDB{},
	}
	validUUID := uuid.New().String()
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	testutils.SetGinParams(c, validUUID, "INVALID$ROLE")
	c.Request, _ = http.NewRequest("GET", "/", nil)
	u := &app.User{}
	rName := new(string)
	err := a.GetRoleDetails(c, u, rName)
	assert.Error(t, err)
	assert.Equal(t, "Invalid rolename in url", err.Error())
}

func TestGetRoleDetails_RoleNameTooLong(t *testing.T) {
	a := &app.App{
		Log: testutils.SetupLogger(),
		DB:  &testutils.MockDB{},
	}
	validUUID := uuid.New().String()
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	testutils.SetGinParams(c, validUUID, "averyveryveryverylongrole")
	c.Request, _ = http.NewRequest("GET", "/", nil)
	u := &app.User{}
	rName := new(string)
	err := a.GetRoleDetails(c, u, rName)
	assert.Error(t, err)
	assert.Equal(t, "role name is too long", err.Error())
}

func TestGetRoleDetails_UserNotFoundByDBError(t *testing.T) {
	a, gdb, mock := testutils.SetupTestAppWithSQLMock(t)
	t.Cleanup(func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("unmet sqlmock expectations: %s", err)
		}
	})
	mock.MatchExpectationsInOrder(false)
	validUUID := uuid.New().String()
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	testutils.SetGinParams(c, validUUID, "validrole")
	c.Request, _ = http.NewRequest("GET", "/", nil)
	u := &app.User{}
	rName := new(string)
	adminId, _ := uuid.Parse(validUUID)
	mock.ExpectQuery(`SELECT \* FROM "users" WHERE "users"."deleted" IS NULL AND "users"."admin_id" = \$1`).
		WithArgs(adminId).
		WillReturnError(gorm.ErrRecordNotFound)
	a.DB = app.NewGormDB(gdb)
	err := a.GetRoleDetails(c, u, rName)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, gorm.ErrRecordNotFound))
}

func TestGetRoleDetails_UserNotFoundEmptyUsername(t *testing.T) {
	a, gdb, mock := testutils.SetupTestAppWithSQLMock(t)
	t.Cleanup(func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("unmet sqlmock expectations: %s", err)
		}
	})
	mock.MatchExpectationsInOrder(false)
	validUUID := uuid.New().String()
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	testutils.SetGinParams(c, validUUID, "validrole")
	c.Request, _ = http.NewRequest("GET", "/", nil)
	u := &app.User{}
	rName := new(string)
	adminId, _ := uuid.Parse(validUUID)
	mock.ExpectQuery(`SELECT \* FROM "users" WHERE "users"."deleted" IS NULL AND "users"."admin_id" = \$1`).
		WithArgs(adminId).
		WillReturnRows(sqlmock.NewRows([]string{
			"admin_id", "username", "password", "last_login", "active", "validated", "created", "updated",
		}).AddRow(validUUID, "", nil, nil, true, true, nil, nil))
	mock.ExpectQuery(`SELECT \* FROM "user_role" WHERE "user_role"."user_admin_id" = \$1`).
		WithArgs(adminId).
		WillReturnRows(sqlmock.NewRows([]string{"user_admin_id", "role_name"}))
	a.DB = app.NewGormDB(gdb)
	err := a.GetRoleDetails(c, u, rName)
	assert.Error(t, err)
	assert.Equal(t, "user not found", err.Error())
}

func TestGetRoleDetails_DBErrorOther(t *testing.T) {
	a, gdb, mock := testutils.SetupTestAppWithSQLMock(t)
	t.Cleanup(func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("unmet sqlmock expectations: %s", err)
		}
	})
	mock.MatchExpectationsInOrder(false)
	validUUID := uuid.New().String()
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	testutils.SetGinParams(c, validUUID, "validrole")
	c.Request, _ = http.NewRequest("GET", "/", nil)
	u := &app.User{}
	rName := new(string)
	adminId, _ := uuid.Parse(validUUID)
	mock.ExpectQuery(`SELECT \* FROM "users" WHERE "users"."deleted" IS NULL AND "users"."admin_id" = \$1`).
		WithArgs(adminId).
		WillReturnError(errors.New("some db error"))
	a.DB = app.NewGormDB(gdb)
	err := a.GetRoleDetails(c, u, rName)
	assert.Error(t, err)
	assert.Equal(t, "some db error", err.Error())
}

func TestGetRoleDetails_HappyPath(t *testing.T) {
	a, gdb, mock := testutils.SetupTestAppWithSQLMock(t)
	t.Cleanup(func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("unmet sqlmock expectations: %s", err)
		}
	})
	mock.MatchExpectationsInOrder(false)
	validUUID := uuid.New().String()
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	testutils.SetGinParams(c, validUUID, "validrole")
	c.Request, _ = http.NewRequest("GET", "/", nil)
	u := &app.User{}
	rName := new(string)
	adminId, _ := uuid.Parse(validUUID)

	// 1. Users query
	mock.ExpectQuery(`SELECT \* FROM "users" WHERE "users"."deleted" IS NULL AND "users"."admin_id" = \$1`).
		WithArgs(adminId).
		WillReturnRows(sqlmock.NewRows([]string{
			"admin_id", "username", "password", "last_login", "active", "validated", "created", "updated",
		}).AddRow(validUUID, "happyuser", nil, nil, true, true, nil, nil))

	// 2. User_role query
	mock.ExpectQuery(`SELECT \* FROM "user_role" WHERE "user_role"."user_admin_id" = \$1`).
		WithArgs(adminId).
		WillReturnRows(sqlmock.NewRows([]string{"user_admin_id", "role_name"}).AddRow(validUUID, "validrole"))

	// 3. Roles query (per error log)
	mock.ExpectQuery(`SELECT \* FROM "roles" WHERE "roles"."name" = \$1`).
		WithArgs("validrole").
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("validrole"))

	a.DB = app.NewGormDB(gdb)
	err := a.GetRoleDetails(c, u, rName)
	assert.NoError(t, err)
	assert.Equal(t, "validrole", *rName)
	assert.Equal(t, validUUID, u.AdminId.String())
	assert.Equal(t, "happyuser", u.Username)
}
