package unit

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/stretchr/testify/require"
)

func TestCreateCreds_HappyPath(t *testing.T) {
	cleanup := testutils.SetupEncryptPasswordMock()
	defer cleanup()
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	user := testutils.CreateTestUserBasic("alice")
	payload := testutils.DefaultCreateCredsPayload()
	body, _ := json.Marshal(payload)
	req := testutils.NewRewindableRequest("POST", "/admin/creds", body)
	c, w := testutils.CreateGinContextWithUser(user)
	c.Request = req

	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO "creds"`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	testutils.ExpectMicroserviceSelect(mock)
	mock.ExpectExec(`INSERT INTO "microservices"`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(`INSERT INTO "role_cred_ms"`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	a.CreateCreds(c)
	require.Equal(t, 201, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	require.Contains(t, resp["message"], "Creds created; credId is [")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateCreds_BadJSONCred(t *testing.T) {
	cleanup := testutils.SetupEncryptPasswordMock()
	defer cleanup()
	a, _, _ := testutils.SetupTestAppWithSQLMock(t)
	user := testutils.CreateTestUserBasic("bob")
	req := testutils.NewRewindableRequest("POST", "/admin/creds", []byte(`{`))
	c, w := testutils.CreateGinContextWithUser(user)
	c.Request = req
	a.CreateCreds(c)
	require.Equal(t, 400, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	require.Equal(t, "Bad request [1]", resp["message"])
}

func TestCreateCreds_InvalidDBType(t *testing.T) {
	cleanup := testutils.SetupEncryptPasswordMock()
	defer cleanup()
	a, _, _ := testutils.SetupTestAppWithSQLMock(t)
	user := testutils.CreateTestUserBasic("carol")
	payload := testutils.DefaultCreateCredsPayload()
	payload["type"] = "notarealdb"
	body, _ := json.Marshal(payload)
	req := testutils.NewRewindableRequest("POST", "/admin/creds", body)
	c, w := testutils.CreateGinContextWithUser(user)
	c.Request = req
	a.CreateCreds(c)
	require.Equal(t, 400, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	require.Equal(t, "Bad request; Incorrect db type", resp["message"])
}

func TestCreateCreds_BadJSONMsIn(t *testing.T) {
	cleanup := testutils.SetupEncryptPasswordMock()
	defer cleanup()
	a, _, _ := testutils.SetupTestAppWithSQLMock(t)
	user := testutils.CreateTestUserBasic("dave")
	payload := testutils.DefaultCreateCredsPayload()
	delete(payload, "ms_name")
	body, _ := json.Marshal(payload)
	req := testutils.NewRewindableRequest("POST", "/admin/creds", body)
	c, w := testutils.CreateGinContextWithUser(user)
	c.Request = req
	a.CreateCreds(c)
	require.Equal(t, 400, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	require.Equal(t, "Bad request [2]", resp["message"])
}

func TestCreateCreds_BadJSONRole(t *testing.T) {
	cleanup := testutils.SetupEncryptPasswordMock()
	defer cleanup()
	a, _, _ := testutils.SetupTestAppWithSQLMock(t)
	user := testutils.CreateTestUserBasic("eve")
	payload := testutils.DefaultCreateCredsPayload()
	delete(payload, "role_name")
	body, _ := json.Marshal(payload)
	req := testutils.NewRewindableRequest("POST", "/admin/creds", body)
	c, w := testutils.CreateGinContextWithUser(user)
	c.Request = req
	a.CreateCreds(c)
	require.Equal(t, 400, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	require.Equal(t, "Bad request [3]", resp["message"])
}

func TestCreateCreds_EncryptCredPass_BadBase64(t *testing.T) {
	original := app.EncryptCredPass
	defer func() { app.EncryptCredPass = original }()
	a, _, _ := testutils.SetupTestAppWithSQLMock(t)
	user := testutils.CreateTestUserBasic("frank")
	payload := testutils.DefaultCreateCredsPayload()
	payload["db_password"] = "not_base64!!"
	body, _ := json.Marshal(payload)
	req := testutils.NewRewindableRequest("POST", "/admin/creds", body)
	c, w := testutils.CreateGinContextWithUser(user)
	c.Request = req
	a.CreateCreds(c)
	require.Equal(t, 400, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	require.Equal(t, "Bad request [4]", resp["message"])
}

func TestCreateCreds_EncryptCredPass_EncryptionFails(t *testing.T) {
	original := app.EncryptCredPass
	defer func() { app.EncryptCredPass = original }()
	os.Setenv("SUPERSECRETKEY", "")
	os.Setenv("SUPERSECRETNONCE", "")
	defer func() {
		os.Unsetenv("SUPERSECRETKEY")
		os.Unsetenv("SUPERSECRETNONCE")
	}()
	a, _, _ := testutils.SetupTestAppWithSQLMock(t)
	user := testutils.CreateTestUserBasic("greg")
	payload := testutils.DefaultCreateCredsPayload()
	body, _ := json.Marshal(payload)
	req := testutils.NewRewindableRequest("POST", "/admin/creds", body)
	c, w := testutils.CreateGinContextWithUser(user)
	c.Request = req
	a.CreateCreds(c)
	require.Equal(t, 400, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	require.Equal(t, "Bad request [4]", resp["message"])
}

func TestCreateCreds_TxFails_CreateCred(t *testing.T) {
	cleanup := testutils.SetupEncryptPasswordMock()
	defer cleanup()
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	user := testutils.CreateTestUserBasic("harry")
	payload := testutils.DefaultCreateCredsPayload()
	body, _ := json.Marshal(payload)
	req := testutils.NewRewindableRequest("POST", "/admin/creds", body)
	c, w := testutils.CreateGinContextWithUser(user)
	c.Request = req

	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO "creds"`).
		WillReturnError(sqlmock.ErrCancelled)
	mock.ExpectRollback()

	a.CreateCreds(c)
	require.Equal(t, 500, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	require.Equal(t, "Something went boom", resp["message"])
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateCreds_TxFails_FirstOrCreateMicroservice(t *testing.T) {
	cleanup := testutils.SetupEncryptPasswordMock()
	defer cleanup()
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	user := testutils.CreateTestUserBasic("irene")
	payload := testutils.DefaultCreateCredsPayload()
	body, _ := json.Marshal(payload)
	req := testutils.NewRewindableRequest("POST", "/admin/creds", body)
	c, w := testutils.CreateGinContextWithUser(user)
	c.Request = req

	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO "creds"`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	testutils.ExpectMicroserviceSelect(mock)
	mock.ExpectExec(`INSERT INTO "microservices"`).
		WillReturnError(sqlmock.ErrCancelled)
	mock.ExpectRollback()

	a.CreateCreds(c)
	require.Equal(t, 500, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	require.Equal(t, "Something went boom", resp["message"])
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateCreds_TxFails_CreateRoleCredMS(t *testing.T) {
	cleanup := testutils.SetupEncryptPasswordMock()
	defer cleanup()
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	user := testutils.CreateTestUserBasic("jane")
	payload := testutils.DefaultCreateCredsPayload()
	body, _ := json.Marshal(payload)
	req := testutils.NewRewindableRequest("POST", "/admin/creds", body)
	c, w := testutils.CreateGinContextWithUser(user)
	c.Request = req

	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO "creds"`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	testutils.ExpectMicroserviceSelect(mock)
	mock.ExpectExec(`INSERT INTO "microservices"`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(`INSERT INTO "role_cred_ms"`).
		WillReturnError(sqlmock.ErrCancelled)
	mock.ExpectRollback()

	a.CreateCreds(c)
	require.Equal(t, 500, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	require.Equal(t, "Something went boom", resp["message"])
	require.NoError(t, mock.ExpectationsWereMet())
}
