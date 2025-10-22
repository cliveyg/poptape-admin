package unit

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/cliveyg/poptape-admin/utils"
	"github.com/stretchr/testify/assert"
)

func TestCheckLoginDetails_HappyPath(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)

	password := "goodpass"
	user := testutils.CreateTestUserBasic("validuser")
	hashed, err := utils.GenerateHashPassword([]byte(password))
	assert.NoError(t, err)
	user.Password = hashed
	login := app.Login{
		Username: user.Username,
		Password: base64.StdEncoding.EncodeToString([]byte(password)),
	}

	rows := sqlmock.NewRows([]string{"admin_id", "username", "password", "validated", "active"}).
		AddRow(user.AdminId, user.Username, user.Password, true, true)
	mock.ExpectQuery(testutils.UserQueryRegex).WillReturnRows(rows)
	roleRows := sqlmock.NewRows([]string{"role_name", "user_admin_id"}).
		AddRow("admin", user.AdminId)
	mock.ExpectQuery(testutils.UserRoleQueryRegex).WithArgs(user.AdminId).WillReturnRows(roleRows)
	rolesRows := sqlmock.NewRows([]string{"name"}).AddRow("admin")
	mock.ExpectQuery(testutils.RolesQueryRegex).WithArgs("admin").WillReturnRows(rolesRows)

	u := app.User{}
	err = a.CheckLoginDetails(&login, &u)
	assert.NoError(t, err)
}

func TestCheckLoginDetails_DBError(t *testing.T) {
	// DO NOT MODIFY (passing test)
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)

	login := app.Login{Username: "nouser", Password: base64.StdEncoding.EncodeToString([]byte("irrelevant"))}
	mock.ExpectQuery(testutils.UserQueryRegex).WillReturnError(errors.New("db error"))

	u := app.User{}
	err := a.CheckLoginDetails(&login, &u)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "db error")
}

func TestCheckLoginDetails_UserNotValidated(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)

	user := testutils.CreateTestUserBasic("notvalidated")
	user.Validated = false
	user.Password = []byte("pass")
	login := app.Login{
		Username: user.Username,
		Password: base64.StdEncoding.EncodeToString([]byte("pass")),
	}

	rows := sqlmock.NewRows([]string{"admin_id", "username", "password", "validated", "active"}).
		AddRow(user.AdminId, user.Username, user.Password, false, true)
	mock.ExpectQuery(testutils.UserQueryRegex).WillReturnRows(rows)
	roleRows := sqlmock.NewRows([]string{"role_name", "user_admin_id"}).
		AddRow("admin", user.AdminId)
	mock.ExpectQuery(testutils.UserRoleQueryRegex).WithArgs(user.AdminId).WillReturnRows(roleRows)
	rolesRows := sqlmock.NewRows([]string{"name"}).AddRow("admin")
	mock.ExpectQuery(testutils.RolesQueryRegex).WithArgs("admin").WillReturnRows(rolesRows)

	u := app.User{}
	err := a.CheckLoginDetails(&login, &u)
	assert.Error(t, err)
	assert.Equal(t, "user not validated", err.Error())
}

func TestCheckLoginDetails_UserNotActive(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)

	user := testutils.CreateTestUserBasic("inactiveuser")
	user.Active = false
	user.Password = []byte("pass")
	login := app.Login{
		Username: user.Username,
		Password: base64.StdEncoding.EncodeToString([]byte("pass")),
	}

	rows := sqlmock.NewRows([]string{"admin_id", "username", "password", "validated", "active"}).
		AddRow(user.AdminId, user.Username, user.Password, true, false)
	mock.ExpectQuery(testutils.UserQueryRegex).WillReturnRows(rows)
	roleRows := sqlmock.NewRows([]string{"role_name", "user_admin_id"}).
		AddRow("admin", user.AdminId)
	mock.ExpectQuery(testutils.UserRoleQueryRegex).WithArgs(user.AdminId).WillReturnRows(roleRows)
	rolesRows := sqlmock.NewRows([]string{"name"}).AddRow("admin")
	mock.ExpectQuery(testutils.RolesQueryRegex).WithArgs("admin").WillReturnRows(rolesRows)

	u := app.User{}
	err := a.CheckLoginDetails(&login, &u)
	assert.Error(t, err)
	assert.Equal(t, "user not active", err.Error())
}

func TestCheckLoginDetails_PasswordBase64DecodeError(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)

	user := testutils.CreateTestUserBasic("badbase64")
	user.Password = []byte("pass")
	login := app.Login{
		Username: user.Username,
		Password: "not_base64!!",
	}

	rows := sqlmock.NewRows([]string{"admin_id", "username", "password", "validated", "active"}).
		AddRow(user.AdminId, user.Username, user.Password, true, true)
	mock.ExpectQuery(testutils.UserQueryRegex).WillReturnRows(rows)
	roleRows := sqlmock.NewRows([]string{"role_name", "user_admin_id"}).
		AddRow("admin", user.AdminId)
	mock.ExpectQuery(testutils.UserRoleQueryRegex).WithArgs(user.AdminId).WillReturnRows(roleRows)
	rolesRows := sqlmock.NewRows([]string{"name"}).AddRow("admin")
	mock.ExpectQuery(testutils.RolesQueryRegex).WithArgs("admin").WillReturnRows(rolesRows)

	u := app.User{}
	err := a.CheckLoginDetails(&login, &u)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "illegal base64")
}

func TestCheckLoginDetails_VerifyPasswordFails(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)

	// Set up user password as a hash of something else, so verification fails
	user := testutils.CreateTestUserBasic("wrongpass")
	hashed, err := utils.GenerateHashPassword([]byte("realpass"))
	assert.NoError(t, err)
	user.Password = hashed
	login := app.Login{
		Username: user.Username,
		Password: base64.StdEncoding.EncodeToString([]byte("wrongpass")), // input pass
	}

	rows := sqlmock.NewRows([]string{"admin_id", "username", "password", "validated", "active"}).
		AddRow(user.AdminId, user.Username, user.Password, true, true)
	mock.ExpectQuery(testutils.UserQueryRegex).WillReturnRows(rows)
	roleRows := sqlmock.NewRows([]string{"role_name", "user_admin_id"}).
		AddRow("admin", user.AdminId)
	mock.ExpectQuery(testutils.UserRoleQueryRegex).WithArgs(user.AdminId).WillReturnRows(roleRows)
	rolesRows := sqlmock.NewRows([]string{"name"}).AddRow("admin")
	mock.ExpectQuery(testutils.RolesQueryRegex).WithArgs("admin").WillReturnRows(rolesRows)

	u := app.User{}
	err = a.CheckLoginDetails(&login, &u)
	assert.Error(t, err)
	assert.Equal(t, "password doesn't match", err.Error())
}
