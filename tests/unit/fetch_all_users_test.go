package unit

import (
	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
)

func TestFetchAllUsers_HappyPath(t *testing.T) {
	appInstance, db := testutils.SetupTestAppWithSQLite()
	defer func() { sqlDB, _ := db.DB(); sqlDB.Close() }()

	testutils.CreateTestRole(t, db, "admin")
	testutils.CreateTestRole(t, db, "super")
	user1 := testutils.CreateTestUser(t, db, "alice")
	user2 := testutils.CreateTestUser(t, db, "bob")

	roleAdmin := &app.Role{Name: "admin"}
	roleSuper := &app.Role{Name: "super"}
	db.Model(&user1).Association("Roles").Append(roleAdmin)
	db.Model(&user2).Association("Roles").Append(roleSuper)

	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	appInstance.FetchAllUsers(c)

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
}

func TestFetchAllUsers_NoUsers(t *testing.T) {
	appInstance, db := testutils.SetupTestAppWithSQLite()
	defer func() { sqlDB, _ := db.DB(); sqlDB.Close() }()
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	appInstance.FetchAllUsers(c)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	users, ok := resp["users"].([]interface{})
	assert.True(t, ok)
	assert.Len(t, users, 0)
}

// Simulate DB error by dropping the 'users' table
func TestFetchAllUsers_DBError(t *testing.T) {
	appInstance, db := testutils.SetupTestAppWithSQLite()
	defer func() { sqlDB, _ := db.DB(); sqlDB.Close() }()

	_ = db.Migrator().DropTable(&app.User{})

	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	appInstance.FetchAllUsers(c)
	require.Equal(t, http.StatusInternalServerError, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	require.Contains(t, resp["message"], "Something went pop")
}
