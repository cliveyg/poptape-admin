package unit

import (
	"errors"
	"net/http"
	"testing"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Happy path: roles found, user has valid role ---
func TestListAllRoles_HappyPath(t *testing.T) {
	a, db, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)

	roles := []app.Role{
		{Name: "admin"},
		{Name: "super"},
		{Name: "user"},
	}
	mock.ExpectQuery(`SELECT \* FROM "roles"`).WillReturnRows(testutils.RoleRows(roles))

	user := testutils.CreateTestUserBasic("alice")
	user.Roles = []app.Role{{Name: "admin"}}
	c, w := testutils.CreateGinContextWithUser(user)

	a.ListAllRoles(c)

	require.Equal(t, http.StatusOK, w.Code)
	out := testutils.ExtractJSONResponse(t, w)
	assert.Contains(t, out, "roles")
	respRoles, ok := out["roles"].([]interface{})
	require.True(t, ok)
	assert.Len(t, respRoles, 3)

	_ = db // silence unused variable warning if needed
}

// --- Error: DB returns error ---
func TestListAllRoles_DBError(t *testing.T) {
	a, db, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)

	mock.ExpectQuery(`SELECT \* FROM "roles"`).
		WillReturnError(errors.New("db failed"))

	user := testutils.CreateTestUserBasic("admin")
	user.Roles = []app.Role{{Name: "admin"}}
	c, w := testutils.CreateGinContextWithUser(user)

	a.ListAllRoles(c)

	require.Equal(t, http.StatusInternalServerError, w.Code)
	out := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, "Something went neee", out["message"])

	_ = db
}

// --- Error: No roles found (empty slice returned) ---
func TestListAllRoles_NoRolesFound(t *testing.T) {
	a, db, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)

	mock.ExpectQuery(`SELECT \* FROM "roles"`).
		WillReturnRows(testutils.RoleRows([]app.Role{}))

	user := testutils.CreateTestUserBasic("admin")
	user.Roles = []app.Role{{Name: "admin"}}
	c, w := testutils.CreateGinContextWithUser(user)

	a.ListAllRoles(c)

	require.Equal(t, http.StatusInternalServerError, w.Code)
	out := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, "Something went neee", out["message"])

	_ = db
}

// --- User does not have a "super" or "admin" role: still lists roles (no access check for response) ---
func TestListAllRoles_UserNoAccessRole(t *testing.T) {
	a, db, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)

	roles := []app.Role{{Name: "user"}}
	mock.ExpectQuery(`SELECT \* FROM "roles"`).WillReturnRows(testutils.RoleRows(roles))

	user := testutils.CreateTestUserBasic("bob")
	user.Roles = []app.Role{{Name: "user"}}
	c, w := testutils.CreateGinContextWithUser(user)

	a.ListAllRoles(c)

	require.Equal(t, http.StatusOK, w.Code)
	out := testutils.ExtractJSONResponse(t, w)
	assert.Contains(t, out, "roles")

	_ = db
}

// --- No user in context, should still list roles if found ---
func TestListAllRoles_NoUserInContext(t *testing.T) {
	a, db, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)

	roles := []app.Role{{Name: "guest"}}
	mock.ExpectQuery(`SELECT \* FROM "roles"`).WillReturnRows(testutils.RoleRows(roles))

	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)

	a.ListAllRoles(c)

	require.Equal(t, http.StatusOK, w.Code)
	out := testutils.ExtractJSONResponse(t, w)
	assert.Contains(t, out, "roles")

	_ = db
}
