package unit

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateUser_HappyPath(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)
	mock.ExpectQuery(`SELECT .*FROM "roles".*WHERE.*"name" = \$1`).WithArgs("admin").
		WillReturnRows(sqlmock.NewRows([]string{"name", "created"}).
			AddRow("admin", time.Date(2025, time.October, 20, 0, 14, 46, 82000000, time.FixedZone("-03", -3*60*60))),
		)
	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO "roles" \("name","created"\) VALUES \(\$1,\$2\) ON CONFLICT DO NOTHING`).
		WithArgs("admin", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 0))
	mock.ExpectExec(`INSERT INTO "user_role" \("user_admin_id","role_name"\) VALUES \(\$1,\$2\) ON CONFLICT DO NOTHING`).
		WithArgs(sqlmock.AnyArg(), "admin").
		WillReturnResult(sqlmock.NewResult(1, 0))
	mock.ExpectExec(`INSERT INTO "users" \("admin_id","username","password","last_login","active","validated","created","updated","deleted"\) VALUES \(\$1,\$2,\$3,\$4,\$5,\$6,\$7,\$8,\$9\)`).
		WithArgs(
			sqlmock.AnyArg(), "testuser", sqlmock.AnyArg(),
			sqlmock.AnyArg(), true, false,
			sqlmock.AnyArg(), sqlmock.AnyArg(), nil,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	origEnv := os.Getenv("ENVIRONMENT")
	defer os.Setenv("ENVIRONMENT", origEnv)
	os.Setenv("ENVIRONMENT", "PROD")

	payload := testutils.NewSignupPayload("testuser", "password123", "password123")
	body, err := json.Marshal(payload)
	require.NoError(t, err)
	c, w := testutils.SetupCreateUserGinContext(body, "dummy-token")

	a.CreateUser(c)
	assert.Equal(t, http.StatusCreated, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Contains(t, resp["message"], "created but not validated")
}

func TestCreateUser_DevMode_Validates(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)
	mock.ExpectQuery(`SELECT .*FROM "roles".*WHERE.*"name" = \$1`).WithArgs("admin").
		WillReturnRows(sqlmock.NewRows([]string{"name", "created"}).
			AddRow("admin", time.Date(2025, time.October, 20, 0, 14, 47, 795000000, time.FixedZone("-03", -3*60*60))),
		)
	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO "roles" \("name","created"\) VALUES \(\$1,\$2\) ON CONFLICT DO NOTHING`).
		WithArgs("admin", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 0))
	mock.ExpectExec(`INSERT INTO "user_role" \("user_admin_id","role_name"\) VALUES \(\$1,\$2\) ON CONFLICT DO NOTHING`).
		WithArgs(sqlmock.AnyArg(), "admin").
		WillReturnResult(sqlmock.NewResult(1, 0))
	mock.ExpectExec(`INSERT INTO "users" \("admin_id","username","password","last_login","active","validated","created","updated","deleted"\) VALUES \(\$1,\$2,\$3,\$4,\$5,\$6,\$7,\$8,\$9\)`).
		WithArgs(
			sqlmock.AnyArg(), "testuser", sqlmock.AnyArg(),
			sqlmock.AnyArg(), true, false,
			sqlmock.AnyArg(), sqlmock.AnyArg(), nil,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO "roles" \("name","created"\) VALUES \(\$1,\$2\) ON CONFLICT DO NOTHING`).
		WithArgs("admin", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 0))
	mock.ExpectExec(`INSERT INTO "user_role" \("user_admin_id","role_name"\) VALUES \(\$1,\$2\) ON CONFLICT DO NOTHING`).
		WithArgs(sqlmock.AnyArg(), "admin").
		WillReturnResult(sqlmock.NewResult(1, 0))
	mock.ExpectExec(`UPDATE "users" SET "username"=\$1,"password"=\$2,"last_login"=\$3,"active"=\$4,"validated"=\$5,"created"=\$6,"updated"=\$7,"deleted"=\$8 WHERE "users"."deleted" IS NULL AND "admin_id" = \$9`).
		WithArgs(
			"testuser",
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			true,
			true,
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			nil,
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	origEnv := os.Getenv("ENVIRONMENT")
	defer os.Setenv("ENVIRONMENT", origEnv)
	os.Setenv("ENVIRONMENT", "DEV")

	payload := testutils.NewSignupPayload("testuser", "password123", "password123")
	body, err := json.Marshal(payload)
	require.NoError(t, err)
	c, w := testutils.SetupCreateUserGinContext(body, "dummy-token")
	a.CreateUser(c)

	assert.Equal(t, http.StatusCreated, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Contains(t, resp["message"], "created and validated")
}

func TestCreateUser_BadRequest(t *testing.T) {
	a, _, _ := testutils.SetupTestAppWithSQLMock(t)
	c, w := testutils.SetupCreateUserGinContext([]byte(`{"username":}`), "dummy-token")
	a.CreateUser(c)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Contains(t, resp["message"], "Bad request [1]")
}

func TestCreateUser_PasswordsDontMatch(t *testing.T) {
	a, _, _ := testutils.SetupTestAppWithSQLMock(t)
	payload := testutils.NewSignupPayload("testuser", "password123", "notthesame")
	body, err := json.Marshal(payload)
	require.NoError(t, err)
	c, w := testutils.SetupCreateUserGinContext(body, "dummy-token")
	a.CreateUser(c)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Contains(t, resp["message"], "Passwords don't match")
}

// FIXED TEST: Bad base64 encoding -- NO DB expectations at all!
func TestCreateUser_BadBase64(t *testing.T) {
	a, _, _ := testutils.SetupTestAppWithSQLMock(t)
	// MANUALLY create the payload with invalid base64
	payload := map[string]string{
		"username":         "testuser",
		"password":         "!!!notbase64!!!",
		"confirm_password": "!!!notbase64!!!",
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)
	c, w := testutils.SetupCreateUserGinContext(body, "dummy-token")
	a.CreateUser(c)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Contains(t, resp["message"], "Bad base64 encoding")
}

func TestCreateUser_DBErrorOnCreate(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)
	mock.ExpectQuery(`SELECT .*FROM "roles".*WHERE.*"name" = \$1`).WithArgs("admin").
		WillReturnRows(sqlmock.NewRows([]string{"name", "created"}).
			AddRow("admin", time.Now()),
		)
	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO "roles" \("name","created"\) VALUES \(\$1,\$2\) ON CONFLICT DO NOTHING`).
		WithArgs("admin", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 0))
	mock.ExpectExec(`INSERT INTO "user_role" \("user_admin_id","role_name"\) VALUES \(\$1,\$2\) ON CONFLICT DO NOTHING`).
		WithArgs(sqlmock.AnyArg(), "admin").
		WillReturnResult(sqlmock.NewResult(1, 0))
	mock.ExpectExec(`INSERT INTO "users" \("admin_id","username","password","last_login","active","validated","created","updated","deleted"\) VALUES \(\$1,\$2,\$3,\$4,\$5,\$6,\$7,\$8,\$9\)`).
		WithArgs(
			sqlmock.AnyArg(), "testuser", sqlmock.AnyArg(),
			sqlmock.AnyArg(), true, false,
			sqlmock.AnyArg(), sqlmock.AnyArg(), nil,
		).
		WillReturnError(assert.AnError)
	mock.ExpectRollback()

	payload := testutils.NewSignupPayload("testuser", "password123", "password123")
	body, err := json.Marshal(payload)
	require.NoError(t, err)
	c, w := testutils.SetupCreateUserGinContext(body, "dummy-token")

	a.CreateUser(c)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Contains(t, resp["message"], "Something went bang [1]")
}

func TestCreateUser_DevMode_DBErrorOnValidate(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)
	mock.ExpectQuery(`SELECT .*FROM "roles".*WHERE.*"name" = \$1`).WithArgs("admin").
		WillReturnRows(sqlmock.NewRows([]string{"name", "created"}).
			AddRow("admin", time.Now()),
		)
	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO "roles" \("name","created"\) VALUES \(\$1,\$2\) ON CONFLICT DO NOTHING`).
		WithArgs("admin", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 0))
	mock.ExpectExec(`INSERT INTO "user_role" \("user_admin_id","role_name"\) VALUES \(\$1,\$2\) ON CONFLICT DO NOTHING`).
		WithArgs(sqlmock.AnyArg(), "admin").
		WillReturnResult(sqlmock.NewResult(1, 0))
	mock.ExpectExec(`INSERT INTO "users" \("admin_id","username","password","last_login","active","validated","created","updated","deleted"\) VALUES \(\$1,\$2,\$3,\$4,\$5,\$6,\$7,\$8,\$9\)`).
		WithArgs(
			sqlmock.AnyArg(), "testuser", sqlmock.AnyArg(),
			sqlmock.AnyArg(), true, false,
			sqlmock.AnyArg(), sqlmock.AnyArg(), nil,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO "roles" \("name","created"\) VALUES \(\$1,\$2\) ON CONFLICT DO NOTHING`).
		WithArgs("admin", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 0))
	mock.ExpectExec(`INSERT INTO "user_role" \("user_admin_id","role_name"\) VALUES \(\$1,\$2\) ON CONFLICT DO NOTHING`).
		WithArgs(sqlmock.AnyArg(), "admin").
		WillReturnResult(sqlmock.NewResult(1, 0))
	mock.ExpectExec(`UPDATE "users" SET "username"=\$1,"password"=\$2,"last_login"=\$3,"active"=\$4,"validated"=\$5,"created"=\$6,"updated"=\$7,"deleted"=\$8 WHERE "users"."deleted" IS NULL AND "admin_id" = \$9`).
		WithArgs(
			"testuser",
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			true,
			true,
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			nil,
			sqlmock.AnyArg(),
		).
		WillReturnError(assert.AnError)
	mock.ExpectRollback()

	origEnv := os.Getenv("ENVIRONMENT")
	defer os.Setenv("ENVIRONMENT", origEnv)
	os.Setenv("ENVIRONMENT", "DEV")

	payload := testutils.NewSignupPayload("testuser", "password123", "password123")
	body, err := json.Marshal(payload)
	require.NoError(t, err)
	c, w := testutils.SetupCreateUserGinContext(body, "dummy-token")
	a.CreateUser(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Contains(t, resp["message"], "Something went bang [3]")
}
