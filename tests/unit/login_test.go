package unit

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/cliveyg/poptape-admin/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestLogin_HappyPath(t *testing.T) {
	cleanup := testutils.SetupJWTEnv()
	defer cleanup()

	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)

	password := "goodpass"
	hashed, err := utils.GenerateHashPassword([]byte(password))
	assert.NoError(t, err)

	user := testutils.CreateTestUserBasic("validuser")
	user.Password = hashed

	login := app.Login{
		Username: user.Username,
		Password: base64.StdEncoding.EncodeToString([]byte(password)),
	}

	// Prepare SQL expectations for CheckLoginDetails
	rows := sqlmock.NewRows([]string{"admin_id", "username", "password", "validated", "active"}).
		AddRow(user.AdminId, user.Username, user.Password, true, true)
	mock.ExpectQuery(testutils.UserQueryRegex).WillReturnRows(rows)
	roleRows := sqlmock.NewRows([]string{"role_name", "user_admin_id"}).
		AddRow("admin", user.AdminId)
	mock.ExpectQuery(testutils.UserRoleQueryRegex).WithArgs(user.AdminId).WillReturnRows(roleRows)
	rolesRows := sqlmock.NewRows([]string{"name"}).AddRow("admin")
	mock.ExpectQuery(testutils.RolesQueryRegex).WithArgs("admin").WillReturnRows(rolesRows)

	// Expect roles insert (for GORM many2many logic)
	mock.ExpectExec(`INSERT INTO "roles" \("name","created"\) VALUES \(\$1,\$2\) ON CONFLICT DO NOTHING`).
		WithArgs("admin", sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(1, 1))

	// Expect user_role insert (for GORM many2many logic)
	mock.ExpectExec(`INSERT INTO "user_role" \("user_admin_id","role_name"\) VALUES \(\$1,\$2\) ON CONFLICT DO NOTHING`).
		WithArgs(user.AdminId, "admin").WillReturnResult(sqlmock.NewResult(1, 1))

	// Save expectation for updating last login
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE "users" SET`).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	// Setup Gin context and recorder
	body, _ := json.Marshal(login)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("POST", "/admin/login", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")

	a.Login(c)

	resp := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, resp, "token")
	assert.NotEmpty(t, resp["token"])
}

func TestLogin_BadRequest(t *testing.T) {
	a, _, _ := testutils.SetupTestAppWithSQLMock(t)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	// Invalid JSON
	c.Request, _ = http.NewRequest("POST", "/admin/login", bytes.NewReader([]byte(`{invalid json`)))
	c.Request.Header.Set("Content-Type", "application/json")

	a.Login(c)

	resp := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "Bad request", resp["message"])
}

func TestLogin_Unauthorized(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)

	password := "goodpass"
	hashed, err := utils.GenerateHashPassword([]byte("otherpass"))
	assert.NoError(t, err)

	user := testutils.CreateTestUserBasic("invaliduser")
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

	body, _ := json.Marshal(login)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("POST", "/admin/login", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")

	a.Login(c)

	resp := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, "Username and/or password incorrect", resp["message"])
}

func TestLogin_JWTFailure(t *testing.T) {
	cleanup := testutils.SetupJWTEnv()
	defer cleanup()

	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)

	password := "goodpass"
	hashed, err := utils.GenerateHashPassword([]byte(password))
	assert.NoError(t, err)

	user := testutils.CreateTestUserBasic("jwtuser")
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

	// Simulate JWT failure
	origGenToken := utils.GenerateToken
	utils.GenerateToken = func(uname string, adminId uuid.UUID) (string, error) {
		return "", errors.New("jwt fail")
	}
	defer func() { utils.GenerateToken = origGenToken }()

	body, _ := json.Marshal(login)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("POST", "/admin/login", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")

	a.Login(c)

	resp := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, "Something went bang", resp["message"])
}

func TestLogin_SaveFailure(t *testing.T) {
	cleanup := testutils.SetupJWTEnv()
	defer cleanup()

	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)

	password := "goodpass"
	hashed, err := utils.GenerateHashPassword([]byte(password))
	assert.NoError(t, err)

	user := testutils.CreateTestUserBasic("savefailuser")
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

	// Expect roles insert (for GORM many2many logic)
	mock.ExpectExec(`INSERT INTO "roles" \("name","created"\) VALUES \(\$1,\$2\) ON CONFLICT DO NOTHING`).
		WithArgs("admin", sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(1, 1))

	// Expect user_role insert (for GORM many2many logic)
	mock.ExpectExec(`INSERT INTO "user_role" \("user_admin_id","role_name"\) VALUES \(\$1,\$2\) ON CONFLICT DO NOTHING`).
		WithArgs(user.AdminId, "admin").WillReturnResult(sqlmock.NewResult(1, 1))

	// Expect Save to fail
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE "users" SET`).WillReturnError(errors.New("last login fail"))
	mock.ExpectRollback()

	body, _ := json.Marshal(login)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("POST", "/admin/login", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")

	a.Login(c)

	resp := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, "Ooops", resp["message"])
}
