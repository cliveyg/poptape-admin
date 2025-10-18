package unit

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/stretchr/testify/require"
)

func TestCreateCreds_HappyPath(t *testing.T) {
	cleanup := testutils.SetupEncryptPasswordMock()
	defer cleanup()

	appInst, gdb := testutils.SetupTestAppWithSQLite()
	defer func() { sqlDB, _ := gdb.DB(); sqlDB.Close() }()

	roleName := "items"
	testutils.CreateTestRole(t, gdb, roleName)
	user := testutils.CreateTestUser(t, gdb, "alice")

	payload := testutils.DefaultCreateCredsPayload()
	body, _ := json.Marshal(payload)
	req := testutils.NewRewindableRequest("POST", "/admin/creds", body)
	c, w := testutils.CreateGinContextWithUser(user)
	c.Request = req

	appInst.CreateCreds(c)
	require.Equal(t, 201, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	require.Contains(t, resp["message"], "Creds created; credId is [")
}

func TestCreateCreds_BadJSONCred(t *testing.T) {
	cleanup := testutils.SetupEncryptPasswordMock()
	defer cleanup()

	appInst, gdb := testutils.SetupTestAppWithSQLite()
	defer func() { sqlDB, _ := gdb.DB(); sqlDB.Close() }()
	user := testutils.CreateTestUser(t, gdb, "bob")

	req := testutils.NewRewindableRequest("POST", "/admin/creds", []byte(`{`))
	c, w := testutils.CreateGinContextWithUser(user)
	c.Request = req
	appInst.CreateCreds(c)
	require.Equal(t, 400, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	require.Equal(t, "Bad request [1]", resp["message"])
}

func TestCreateCreds_InvalidDBType(t *testing.T) {
	cleanup := testutils.SetupEncryptPasswordMock()
	defer cleanup()

	appInst, gdb := testutils.SetupTestAppWithSQLite()
	defer func() { sqlDB, _ := gdb.DB(); sqlDB.Close() }()
	testutils.CreateTestRole(t, gdb, "items")
	user := testutils.CreateTestUser(t, gdb, "carol")

	payload := testutils.DefaultCreateCredsPayload()
	payload["type"] = "notarealdb"
	body, _ := json.Marshal(payload)
	req := testutils.NewRewindableRequest("POST", "/admin/creds", body)
	c, w := testutils.CreateGinContextWithUser(user)
	c.Request = req

	appInst.CreateCreds(c)
	require.Equal(t, 400, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	require.Equal(t, "Bad request; Incorrect db type", resp["message"])
}

func TestCreateCreds_BadJSONMsIn(t *testing.T) {
	cleanup := testutils.SetupEncryptPasswordMock()
	defer cleanup()

	appInst, gdb := testutils.SetupTestAppWithSQLite()
	defer func() { sqlDB, _ := gdb.DB(); sqlDB.Close() }()
	testutils.CreateTestRole(t, gdb, "items")
	user := testutils.CreateTestUser(t, gdb, "dave")

	payload := testutils.DefaultCreateCredsPayload()
	delete(payload, "ms_name")
	body, _ := json.Marshal(payload)
	req := testutils.NewRewindableRequest("POST", "/admin/creds", body)
	c, w := testutils.CreateGinContextWithUser(user)
	c.Request = req

	appInst.CreateCreds(c)
	require.Equal(t, 400, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	require.Equal(t, "Bad request [2]", resp["message"])
}

func TestCreateCreds_BadJSONRole(t *testing.T) {
	cleanup := testutils.SetupEncryptPasswordMock()
	defer cleanup()

	appInst, gdb := testutils.SetupTestAppWithSQLite()
	defer func() { sqlDB, _ := gdb.DB(); sqlDB.Close() }()
	testutils.CreateTestRole(t, gdb, "items")
	user := testutils.CreateTestUser(t, gdb, "eve")

	payload := testutils.DefaultCreateCredsPayload()
	delete(payload, "role_name")
	body, _ := json.Marshal(payload)
	req := testutils.NewRewindableRequest("POST", "/admin/creds", body)
	c, w := testutils.CreateGinContextWithUser(user)
	c.Request = req

	appInst.CreateCreds(c)
	require.Equal(t, 400, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	require.Equal(t, "Bad request [3]", resp["message"])
}

// This test does NOT mock EncryptCredPass: it expects a bad base64 decode error from real implementation
func TestCreateCreds_EncryptCredPass_BadBase64(t *testing.T) {
	original := app.EncryptCredPass
	defer func() { app.EncryptCredPass = original }()

	appInst, gdb := testutils.SetupTestAppWithSQLite()
	defer func() { sqlDB, _ := gdb.DB(); sqlDB.Close() }()
	testutils.CreateTestRole(t, gdb, "items")
	user := testutils.CreateTestUser(t, gdb, "frank")

	payload := testutils.DefaultCreateCredsPayload()
	payload["db_password"] = "not_base64!!"
	body, _ := json.Marshal(payload)
	req := testutils.NewRewindableRequest("POST", "/admin/creds", body)
	c, w := testutils.CreateGinContextWithUser(user)
	c.Request = req

	appInst.CreateCreds(c)
	require.Equal(t, 400, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	require.Equal(t, "Bad request [4]", resp["message"])
}

// This test does NOT mock EncryptCredPass: it expects a failure due to env vars
func TestCreateCreds_EncryptCredPass_EncryptionFails(t *testing.T) {
	original := app.EncryptCredPass
	defer func() { app.EncryptCredPass = original }()

	os.Setenv("SUPERSECRETKEY", "")
	os.Setenv("SUPERSECRETNONCE", "")
	defer func() {
		os.Unsetenv("SUPERSECRETKEY")
		os.Unsetenv("SUPERSECRETNONCE")
	}()

	appInst, gdb := testutils.SetupTestAppWithSQLite()
	defer func() { sqlDB, _ := gdb.DB(); sqlDB.Close() }()
	testutils.CreateTestRole(t, gdb, "items")
	user := testutils.CreateTestUser(t, gdb, "greg")

	payload := testutils.DefaultCreateCredsPayload()
	body, _ := json.Marshal(payload)
	req := testutils.NewRewindableRequest("POST", "/admin/creds", body)
	c, w := testutils.CreateGinContextWithUser(user)
	c.Request = req

	appInst.CreateCreds(c)
	require.Equal(t, 400, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	require.Equal(t, "Bad request [4]", resp["message"])
}

func TestCreateCreds_TxFails_CreateCred(t *testing.T) {
	cleanup := testutils.SetupEncryptPasswordMock()
	defer cleanup()

	appInst, gdb := testutils.SetupTestAppWithSQLite()
	defer func() { sqlDB, _ := gdb.DB(); sqlDB.Close() }()
	roleName := "items"
	testutils.CreateTestRole(t, gdb, roleName)
	user := testutils.CreateTestUser(t, gdb, "harry")

	// Insert a credential with a unique db_name
	payload := testutils.DefaultCreateCredsPayload()
	body, _ := json.Marshal(payload)
	req := testutils.NewRewindableRequest("POST", "/admin/creds", body)
	c, w := testutils.CreateGinContextWithUser(user)
	c.Request = req
	appInst.CreateCreds(c)
	require.Equal(t, 201, w.Code)

	// Submit again with the same db_name to cause a unique constraint violation
	user2 := testutils.CreateTestUser(t, gdb, "harry2")
	payload2 := testutils.DefaultCreateCredsPayload()
	body2, _ := json.Marshal(payload2)
	req2 := testutils.NewRewindableRequest("POST", "/admin/creds", body2)
	c2, w2 := testutils.CreateGinContextWithUser(user2)
	c2.Request = req2
	appInst.CreateCreds(c2)
	require.Equal(t, 500, w2.Code)
	resp2 := testutils.ExtractJSONResponse(t, w2)
	require.Equal(t, "Something went boom", resp2["message"])
}

func TestCreateCreds_TxFails_FirstOrCreateMicroservice(t *testing.T) {
	cleanup := testutils.SetupEncryptPasswordMock()
	defer cleanup()

	appInst, gdb := testutils.SetupTestAppWithSQLite()
	defer func() { sqlDB, _ := gdb.DB(); sqlDB.Close() }()
	testutils.CreateTestRole(t, gdb, "items")
	user := testutils.CreateTestUser(t, gdb, "irene")

	payload := testutils.DefaultCreateCredsPayload()
	delete(payload, "ms_name")
	body, _ := json.Marshal(payload)
	req := testutils.NewRewindableRequest("POST", "/admin/creds", body)
	c, w := testutils.CreateGinContextWithUser(user)
	c.Request = req

	appInst.CreateCreds(c)
	require.Equal(t, 400, w.Code)
}

func TestCreateCreds_TxFails_CreateRoleCredMS(t *testing.T) {
	cleanup := testutils.SetupEncryptPasswordMock()
	defer cleanup()

	appInst, gdb := testutils.SetupTestAppWithSQLite()
	defer func() { sqlDB, _ := gdb.DB(); sqlDB.Close() }()

	testutils.CreateTestRole(t, gdb, "items")
	user := testutils.CreateTestUser(t, gdb, "jane")

	testutils.ForceCreateError(gdb)

	payload := testutils.DefaultCreateCredsPayload()
	payload["role_name"] = "nonexistentrole"
	body, _ := json.Marshal(payload)
	req := testutils.NewRewindableRequest("POST", "/admin/creds", body)
	c, w := testutils.CreateGinContextWithUser(user)
	c.Request = req
	appInst.CreateCreds(c)

	require.Equal(t, 500, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	require.Equal(t, "Something went boom", resp["message"])
}
