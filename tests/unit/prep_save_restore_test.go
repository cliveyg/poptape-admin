package unit

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestPrepSaveRestore_HappyPath(t *testing.T) {
	a, gdb, mock := testutils.SetupTestAppWithSQLMock(t)
	defer func() { _ = gdb }()
	mock.MatchExpectationsInOrder(false)

	credId := uuid.New()
	msId := uuid.New()
	dbName := "testdb"
	tabName := "testtab"
	mode := "schema"
	user := testutils.CreateTestUserBasic("testuser")

	c, _ := testutils.CreateGinContextWithUser(user)
	c.Params = []gin.Param{
		{Key: "db", Value: dbName},
		{Key: "tab", Value: tabName},
		{Key: "cred_id", Value: credId.String()},
		{Key: "ms_id", Value: msId.String()},
	}
	c.Set("cred_id", credId.String())
	c.Set("ms_id", msId.String())
	c.Request, _ = http.NewRequest("GET", fmt.Sprintf("/dummy?mode=%s", mode), nil)

	expectedCred := app.Cred{CredId: credId, DBName: dbName}
	rows := sqlmock.NewRows([]string{"cred_id", "db_name"}).AddRow(credId.String(), dbName)
	mock.ExpectQuery(`SELECT \* FROM "creds" WHERE "creds"."cred_id" =.*`).WillReturnRows(rows)

	args := &app.PrepSaveRestoreArgs{
		Ctx:     c,
		DBName:  dbName,
		TabColl: tabName,
		Mode:    mode,
	}
	result := a.PrepSaveRestore(args)
	require.NoError(t, result.Error)
	require.Equal(t, http.StatusOK, result.StatusCode)
	require.Equal(t, dbName, result.DBName)
	require.Equal(t, tabName, result.TabColl)
	require.Equal(t, mode, result.Mode)
	require.Equal(t, expectedCred.CredId, result.Creds.CredId)
	require.Equal(t, expectedCred.DBName, result.Creds.DBName)
	require.Equal(t, user.Username, result.User.Username)
	require.Equal(t, msId, result.MSId)
}

func TestPrepSaveRestore_InvalidMode(t *testing.T) {
	a, _, _ := testutils.SetupTestAppWithSQLMock(t)
	user := testutils.CreateTestUserBasic("user1")
	c, _ := testutils.CreateGinContextWithUser(user)
	c.Params = []gin.Param{
		{Key: "db", Value: "somedb"},
		{Key: "tab", Value: "sometab"},
		{Key: "cred_id", Value: uuid.New().String()},
		{Key: "ms_id", Value: uuid.New().String()},
	}
	c.Set("cred_id", c.Param("cred_id"))
	c.Set("ms_id", c.Param("ms_id"))
	c.Request, _ = http.NewRequest("GET", "/dummy?mode=badmode", nil)

	args := &app.PrepSaveRestoreArgs{
		Ctx:     c,
		DBName:  "somedb",
		TabColl: "sometab",
		Mode:    "badmode",
	}
	result := a.PrepSaveRestore(args)
	require.Error(t, result.Error)
	require.Equal(t, http.StatusBadRequest, result.StatusCode)
	require.Contains(t, result.Error.Error(), "Invalid mode value")
}

func TestPrepSaveRestore_InvalidDbParam(t *testing.T) {
	a, _, _ := testutils.SetupTestAppWithSQLMock(t)
	user := testutils.CreateTestUserBasic("user1")
	c, _ := testutils.CreateGinContextWithUser(user)
	c.Params = []gin.Param{
		{Key: "db", Value: "bad!"},
		{Key: "tab", Value: "sometab"},
		{Key: "cred_id", Value: uuid.New().String()},
		{Key: "ms_id", Value: uuid.New().String()},
	}
	c.Set("cred_id", c.Param("cred_id"))
	c.Set("ms_id", c.Param("ms_id"))
	c.Request, _ = http.NewRequest("GET", "/dummy?mode=schema", nil)

	args := &app.PrepSaveRestoreArgs{
		Ctx:     c,
		DBName:  "bad!",
		TabColl: "sometab",
		Mode:    "schema",
	}
	result := a.PrepSaveRestore(args)
	require.Error(t, result.Error)
	require.Equal(t, http.StatusBadRequest, result.StatusCode)
	require.Contains(t, result.Error.Error(), "Invalid data input for db param")
}

func TestPrepSaveRestore_InvalidTabParam(t *testing.T) {
	a, _, _ := testutils.SetupTestAppWithSQLMock(t)
	user := testutils.CreateTestUserBasic("user1")
	c, _ := testutils.CreateGinContextWithUser(user)
	c.Params = []gin.Param{
		{Key: "db", Value: "somedb"},
		{Key: "tab", Value: "bad!"},
		{Key: "cred_id", Value: uuid.New().String()},
		{Key: "ms_id", Value: uuid.New().String()},
	}
	c.Set("cred_id", c.Param("cred_id"))
	c.Set("ms_id", c.Param("ms_id"))
	c.Request, _ = http.NewRequest("GET", "/dummy?mode=schema", nil)

	args := &app.PrepSaveRestoreArgs{
		Ctx:     c,
		DBName:  "somedb",
		TabColl: "bad!",
		Mode:    "schema",
	}
	result := a.PrepSaveRestore(args)
	require.Error(t, result.Error)
	require.Equal(t, http.StatusBadRequest, result.StatusCode)
	require.Contains(t, result.Error.Error(), "Invalid data input for table/collection param")
}

func TestPrepSaveRestore_GetUUIDFromParams_CredIdError(t *testing.T) {
	a, _, _ := testutils.SetupTestAppWithSQLMock(t)
	user := testutils.CreateTestUserBasic("user1")
	c, _ := testutils.CreateGinContextWithUser(user)
	c.Params = []gin.Param{
		{Key: "db", Value: "somedb"},
		{Key: "tab", Value: "sometab"},
		{Key: "cred_id", Value: "not-a-uuid"},
		{Key: "ms_id", Value: uuid.New().String()},
	}
	// Do NOT set c.Set("cred_id", ...) -- so GetUUIDFromParams fails
	c.Request, _ = http.NewRequest("GET", "/dummy?mode=schema", nil)

	args := &app.PrepSaveRestoreArgs{
		Ctx:     c,
		DBName:  "somedb",
		TabColl: "sometab",
		Mode:    "schema",
	}
	result := a.PrepSaveRestore(args)
	require.Error(t, result.Error)
	require.Equal(t, http.StatusBadRequest, result.StatusCode)
	require.Contains(t, result.Error.Error(), "Error getting uuid from cred param")
}

func TestPrepSaveRestore_GetUUIDFromParams_MsIdError(t *testing.T) {
	a, _, _ := testutils.SetupTestAppWithSQLMock(t)
	user := testutils.CreateTestUserBasic("user1")
	c, _ := testutils.CreateGinContextWithUser(user)
	c.Params = []gin.Param{
		{Key: "db", Value: "somedb"},
		{Key: "tab", Value: "sometab"},
		{Key: "cred_id", Value: uuid.New().String()},
		{Key: "ms_id", Value: "not-a-uuid"},
	}
	c.Set("cred_id", c.Param("cred_id"))
	// Do NOT set c.Set("ms_id", ...) so GetUUIDFromParams fails
	c.Request, _ = http.NewRequest("GET", "/dummy?mode=schema", nil)

	args := &app.PrepSaveRestoreArgs{
		Ctx:     c,
		DBName:  "somedb",
		TabColl: "sometab",
		Mode:    "schema",
	}
	result := a.PrepSaveRestore(args)
	require.Error(t, result.Error)
	require.Equal(t, http.StatusBadRequest, result.StatusCode)
	require.Contains(t, result.Error.Error(), "Error getting uuid from ms param")
}

func TestPrepSaveRestore_CredsNotFound(t *testing.T) {
	a, gdb, mock := testutils.SetupTestAppWithSQLMock(t)
	defer func() { _ = gdb }()
	mock.MatchExpectationsInOrder(false)

	credId := uuid.New()
	msId := uuid.New()
	user := testutils.CreateTestUserBasic("user1")
	c, _ := testutils.CreateGinContextWithUser(user)
	c.Params = []gin.Param{
		{Key: "db", Value: "somedb"},
		{Key: "tab", Value: "sometab"},
		{Key: "cred_id", Value: credId.String()},
		{Key: "ms_id", Value: msId.String()},
	}
	c.Set("cred_id", credId.String())
	c.Set("ms_id", msId.String())
	c.Request, _ = http.NewRequest("GET", "/dummy?mode=schema", nil)

	mock.ExpectQuery(`SELECT \* FROM "creds" WHERE "creds"."cred_id" =.*`).WillReturnRows(sqlmock.NewRows([]string{"cred_id", "db_name"})) // No rows

	args := &app.PrepSaveRestoreArgs{
		Ctx:     c,
		DBName:  "somedb",
		TabColl: "sometab",
		Mode:    "schema",
	}
	result := a.PrepSaveRestore(args)
	require.Error(t, result.Error)
	require.Equal(t, http.StatusNotFound, result.StatusCode)
	require.Contains(t, result.Error.Error(), "Creds not found")
}

func TestPrepSaveRestore_DBError(t *testing.T) {
	a, gdb, mock := testutils.SetupTestAppWithSQLMock(t)
	defer func() { _ = gdb }()
	mock.MatchExpectationsInOrder(false)

	credId := uuid.New()
	msId := uuid.New()
	user := testutils.CreateTestUserBasic("user1")
	c, _ := testutils.CreateGinContextWithUser(user)
	c.Params = []gin.Param{
		{Key: "db", Value: "somedb"},
		{Key: "tab", Value: "sometab"},
		{Key: "cred_id", Value: credId.String()},
		{Key: "ms_id", Value: msId.String()},
	}
	c.Set("cred_id", credId.String())
	c.Set("ms_id", msId.String())
	c.Request, _ = http.NewRequest("GET", "/dummy?mode=schema", nil)

	mock.ExpectQuery(`SELECT \* FROM "creds" WHERE "creds"."cred_id" =.*`).WillReturnError(fmt.Errorf("db is down"))

	args := &app.PrepSaveRestoreArgs{
		Ctx:     c,
		DBName:  "somedb",
		TabColl: "sometab",
		Mode:    "schema",
	}
	result := a.PrepSaveRestore(args)
	require.Error(t, result.Error)
	require.Equal(t, http.StatusInternalServerError, result.StatusCode)
	require.Contains(t, result.Error.Error(), "Something went pop")
}

func TestPrepSaveRestore_DBNameMismatch(t *testing.T) {
	a, gdb, mock := testutils.SetupTestAppWithSQLMock(t)
	defer func() { _ = gdb }()
	mock.MatchExpectationsInOrder(false)

	credId := uuid.New()
	msId := uuid.New()
	dbName := "requested_db"
	realDbName := "actual_db"
	user := testutils.CreateTestUserBasic("user1")
	c, _ := testutils.CreateGinContextWithUser(user)
	c.Params = []gin.Param{
		{Key: "db", Value: dbName},
		{Key: "tab", Value: "sometab"},
		{Key: "cred_id", Value: credId.String()},
		{Key: "ms_id", Value: msId.String()},
	}
	c.Set("cred_id", credId.String())
	c.Set("ms_id", msId.String())
	c.Request, _ = http.NewRequest("GET", "/dummy?mode=schema", nil)

	rows := sqlmock.NewRows([]string{"cred_id", "db_name"}).AddRow(credId.String(), realDbName)
	mock.ExpectQuery(`SELECT \* FROM "creds" WHERE "creds"."cred_id" =.*`).WillReturnRows(rows)

	args := &app.PrepSaveRestoreArgs{
		Ctx:     c,
		DBName:  dbName,
		TabColl: "sometab",
		Mode:    "schema",
	}
	result := a.PrepSaveRestore(args)
	require.Error(t, result.Error)
	require.Equal(t, http.StatusNotFound, result.StatusCode)
	require.Contains(t, result.Error.Error(), "DB name is invalid")
}
