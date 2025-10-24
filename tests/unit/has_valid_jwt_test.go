package unit

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/cliveyg/poptape-admin/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// --- Happy Path ---
func TestHasValidJWT_HappyPath(t *testing.T) {
	cleanup := testutils.SetupJWTEnv()
	defer cleanup()

	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)

	// Create a valid token
	adminID := uuid.New()
	token, err := utils.GenerateToken("alice", adminID)
	assert.NoError(t, err)

	// Expect DB query: Find user by admin_id and deleted is NULL
	mock.ExpectQuery(`SELECT \* FROM "users" WHERE "users"\."deleted" IS NULL AND "users"\."admin_id" = \$1`).
		WithArgs(adminID.String()).
		WillReturnRows(sqlmock.NewRows([]string{
			"admin_id", "username", "password", "last_login", "active", "validated", "created", "updated",
		}).AddRow(adminID.String(), "alice", []byte("irrelevant"), time.Now(), true, true, time.Now(), time.Now()))

	// Preload Roles (simulate single admin role)
	mock.ExpectQuery(`SELECT \* FROM "user_role" WHERE "user_role"\."user_admin_id" = \$1`).
		WithArgs(adminID.String()).
		WillReturnRows(sqlmock.NewRows([]string{"user_admin_id", "role_name"}).AddRow(adminID.String(), "admin"))

	// Roles table join
	mock.ExpectQuery(`SELECT \* FROM "roles" WHERE "roles"\."name" = \$1`).
		WithArgs("admin").
		WillReturnRows(sqlmock.NewRows([]string{"name", "created"}).AddRow("admin", time.Now()))

	c := testutils.SetupJWTHeaderContext(token)
	result := a.HasValidJWT(c)
	assert.True(t, result)
	assert.NotNil(t, c.MustGet("user"))
	assert.NoError(t, mock.ExpectationsWereMet())
}

// --- Error: ShouldBindHeader fails ---
func TestHasValidJWT_MissingHeader(t *testing.T) {
	a, _, _ := testutils.SetupTestAppWithSQLMock(t)
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	// Attach a valid http.Request, but do NOT set any headers
	req, _ := http.NewRequest("GET", "/", nil)
	c.Request = req

	result := a.HasValidJWT(c)
	assert.False(t, result)
}

// --- Error: Invalid Token ---
func TestHasValidJWT_InvalidToken(t *testing.T) {
	cleanup := testutils.SetupJWTEnv()
	defer cleanup()

	a, _, _ := testutils.SetupTestAppWithSQLMock(t)
	c := testutils.SetupJWTHeaderContext("not_a_token")
	result := a.HasValidJWT(c)
	assert.False(t, result)
}

// --- Error: Invalid UUID in Claims ---
func TestHasValidJWT_InvalidUUID(t *testing.T) {
	cleanup := testutils.SetupJWTEnv()
	defer cleanup()
	a, _, _ := testutils.SetupTestAppWithSQLMock(t)

	// Create token with bad AdminId
	claims := &utils.Claims{
		Username: "bob",
		AdminId:  "not-a-uuid",
		Exp:      time.Now().Add(time.Hour).Unix(),
	}
	origParseToken := utils.ParseToken
	utils.ParseToken = func(token string) (*utils.Claims, error) {
		return claims, nil
	}
	defer func() { utils.ParseToken = origParseToken }()

	// Generate a dummy token
	c := testutils.SetupJWTHeaderContext("dummy")
	result := a.HasValidJWT(c)
	assert.False(t, result)
}

// --- Error: DB returns error on Find ---
func TestHasValidJWT_DBError(t *testing.T) {
	cleanup := testutils.SetupJWTEnv()
	defer cleanup()
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)

	adminID := uuid.New()
	token, err := utils.GenerateToken("alice", adminID)
	assert.NoError(t, err)

	// DB error simulation
	mock.ExpectQuery(`SELECT \* FROM "users" WHERE "users"\."deleted" IS NULL AND "users"\."admin_id" = \$1`).
		WithArgs(adminID.String()).
		WillReturnError(errors.New("db error"))

	c := testutils.SetupJWTHeaderContext(token)
	result := a.HasValidJWT(c)
	assert.False(t, result)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// --- Error: User not validated ---
func TestHasValidJWT_UserNotValidated(t *testing.T) {
	cleanup := testutils.SetupJWTEnv()
	defer cleanup()
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)

	adminID := uuid.New()
	token, err := utils.GenerateToken("bob", adminID)
	assert.NoError(t, err)

	mock.ExpectQuery(`SELECT \* FROM "users" WHERE "users"\."deleted" IS NULL AND "users"\."admin_id" = \$1`).
		WithArgs(adminID.String()).
		WillReturnRows(sqlmock.NewRows([]string{
			"admin_id", "username", "password", "last_login", "active", "validated", "created", "updated",
		}).AddRow(adminID.String(), "bob", []byte("irrelevant"), time.Now(), true, false, time.Now(), time.Now()))

	// Preload Roles (simulate single admin role)
	mock.ExpectQuery(`SELECT \* FROM "user_role" WHERE "user_role"\."user_admin_id" = \$1`).
		WithArgs(adminID.String()).
		WillReturnRows(sqlmock.NewRows([]string{"user_admin_id", "role_name"}).AddRow(adminID.String(), "admin"))

	// Roles table join
	mock.ExpectQuery(`SELECT \* FROM "roles" WHERE "roles"\."name" = \$1`).
		WithArgs("admin").
		WillReturnRows(sqlmock.NewRows([]string{"name", "created"}).AddRow("admin", time.Now()))

	c := testutils.SetupJWTHeaderContext(token)
	result := a.HasValidJWT(c)
	assert.False(t, result)
	assert.NoError(t, mock.ExpectationsWereMet())
}
