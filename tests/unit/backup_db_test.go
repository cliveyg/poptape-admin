package unit

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestBackupDB_HappyPath1_Postgres(t *testing.T) {
	user := testutils.CreateTestUserBasic("backupuser")
	c, w := testutils.CreateGinContextWithUser(user)

	dbName := "mydb"
	tabName := "mytable"
	mode := "schema"
	msId := uuid.New()
	credId := uuid.New()
	c.Params = []gin.Param{
		{Key: "db", Value: dbName},
		{Key: "tab", Value: tabName},
		{Key: "cred_id", Value: credId.String()},
		{Key: "ms_id", Value: msId.String()},
	}
	c.Set("cred_id", credId.String())
	c.Set("ms_id", msId.String())
	c.Request, _ = http.NewRequest("GET", "/dummy?mode="+mode, nil)

	expectedCreds := app.Cred{
		CredId:     credId,
		DBName:     dbName,
		Type:       "postgres",
		DBPort:     "5432",
		DBUsername: "testuser",
		Host:       "localhost",
	}
	expectedMSID := msId
	expectedResult := &app.PrepSaveRestoreResult{
		StatusCode: http.StatusOK,
		Error:      nil,
		Creds:      expectedCreds,
		User:       user,
		MSId:       expectedMSID,
		DBName:     dbName,
		TabColl:    tabName,
		Mode:       mode,
	}

	var bytesWritten int64 = 12345
	mockHooks := &testutils.MockHooks{
		PrepSaveRestoreFunc: func(args *app.PrepSaveRestoreArgs) *app.PrepSaveRestoreResult {
			return expectedResult
		},
		BackupPostgresFunc: func(args *app.BackupDBArgs) error {
			if args.Creds.Type != "postgres" {
				t.Fatalf("BackupPostgres called with wrong type: %s", args.Creds.Type)
			}
			*args.BytesWritten = bytesWritten
			return nil
		},
		BackupMongoFunc: func(args *app.BackupDBArgs) error {
			t.Fatalf("BackupMongo should not be called in postgres happy path")
			return nil
		},
	}

	appInstance := &app.App{}
	appInstance.Log = testutils.CreateTestLogger()
	appInstance.Hooks = mockHooks

	appInstance.BackupDB(c)

	require.Equal(t, http.StatusCreated, w.Code)
	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Equal(t, resp["message"], "Table [mytable] from [mydb] postgres db saved")
	require.Equal(t, float64(bytesWritten), resp["no_of_bytes"])
	require.NotEmpty(t, resp["save_id"])
}

func TestBackupDB_HappyPath2_Postgres(t *testing.T) {
	user := testutils.CreateTestUserBasic("backupuser")
	c, w := testutils.CreateGinContextWithUser(user)

	dbName := "mydb"
	mode := "schema"
	msId := uuid.New()
	credId := uuid.New()
	c.Params = []gin.Param{
		{Key: "db", Value: dbName},
		{Key: "cred_id", Value: credId.String()},
		{Key: "ms_id", Value: msId.String()},
	}
	c.Set("cred_id", credId.String())
	c.Set("ms_id", msId.String())
	c.Request, _ = http.NewRequest("GET", "/dummy?mode="+mode, nil)

	expectedCreds := app.Cred{
		CredId:     credId,
		DBName:     dbName,
		Type:       "postgres",
		DBPort:     "5432",
		DBUsername: "testuser",
		Host:       "localhost",
	}
	expectedMSID := msId
	expectedResult := &app.PrepSaveRestoreResult{
		StatusCode: http.StatusOK,
		Error:      nil,
		Creds:      expectedCreds,
		User:       user,
		MSId:       expectedMSID,
		DBName:     dbName,
		TabColl:    "",
		Mode:       mode,
	}

	var bytesWritten int64 = 12345
	mockHooks := &testutils.MockHooks{
		PrepSaveRestoreFunc: func(args *app.PrepSaveRestoreArgs) *app.PrepSaveRestoreResult {
			return expectedResult
		},
		BackupPostgresFunc: func(args *app.BackupDBArgs) error {
			if args.Creds.Type != "postgres" {
				t.Fatalf("BackupPostgres called with wrong type: %s", args.Creds.Type)
			}
			*args.BytesWritten = bytesWritten
			return nil
		},
		BackupMongoFunc: func(args *app.BackupDBArgs) error {
			t.Fatalf("BackupMongo should not be called in postgres happy path")
			return nil
		},
	}

	appInstance := &app.App{}
	appInstance.Log = testutils.CreateTestLogger()
	appInstance.Hooks = mockHooks

	appInstance.BackupDB(c)

	require.Equal(t, http.StatusCreated, w.Code)
	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Equal(t, resp["message"], "[mydb] postgres db saved")
	require.Equal(t, float64(bytesWritten), resp["no_of_bytes"])
	require.NotEmpty(t, resp["save_id"])
}

func TestBackupDB_HappyPath1_Mongo(t *testing.T) {
	user := testutils.CreateTestUserBasic("backupuser")
	c, w := testutils.CreateGinContextWithUser(user)

	dbName := "mydb"
	tabName := "mycollection"
	mode := "all"
	msId := uuid.New()
	credId := uuid.New()
	c.Params = []gin.Param{
		{Key: "db", Value: dbName},
		{Key: "tab", Value: tabName},
		{Key: "cred_id", Value: credId.String()},
		{Key: "ms_id", Value: msId.String()},
	}
	c.Set("cred_id", credId.String())
	c.Set("ms_id", msId.String())
	c.Request, _ = http.NewRequest("GET", "/dummy?mode="+mode, nil)

	expectedCreds := app.Cred{
		CredId:     credId,
		DBName:     dbName,
		Type:       "mongo",
		DBPort:     "27017",
		DBUsername: "testmongo",
		Host:       "localhost",
	}
	expectedMSID := msId
	expectedResult := &app.PrepSaveRestoreResult{
		StatusCode: http.StatusOK,
		Error:      nil,
		Creds:      expectedCreds,
		User:       user,
		MSId:       expectedMSID,
		DBName:     dbName,
		TabColl:    tabName,
		Mode:       mode,
	}

	var bytesWritten int64 = 54321
	mockHooks := &testutils.MockHooks{
		PrepSaveRestoreFunc: func(args *app.PrepSaveRestoreArgs) *app.PrepSaveRestoreResult {
			return expectedResult
		},
		BackupPostgresFunc: func(args *app.BackupDBArgs) error {
			t.Fatalf("BackupPostgres should not be called in mongo happy path")
			return nil
		},
		BackupMongoFunc: func(args *app.BackupDBArgs) error {
			if args.Creds.Type != "mongo" {
				t.Fatalf("BackupMongo called with wrong type: %s", args.Creds.Type)
			}
			*args.BytesWritten = bytesWritten
			return nil
		},
	}

	appInstance := &app.App{}
	appInstance.Log = testutils.CreateTestLogger()
	appInstance.Hooks = mockHooks

	appInstance.BackupDB(c)

	require.Equal(t, http.StatusCreated, w.Code)
	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Equal(t, resp["message"], "Collection [mycollection] from [mydb] db saved")
	require.Equal(t, float64(bytesWritten), resp["no_of_bytes"])
	require.NotEmpty(t, resp["save_id"])
}

func TestBackupDB_HappyPath2_Mongo(t *testing.T) {
	user := testutils.CreateTestUserBasic("backupuser")
	c, w := testutils.CreateGinContextWithUser(user)

	dbName := "mydb"
	mode := "all"
	msId := uuid.New()
	credId := uuid.New()
	c.Params = []gin.Param{
		{Key: "db", Value: dbName},
		{Key: "cred_id", Value: credId.String()},
		{Key: "ms_id", Value: msId.String()},
	}
	c.Set("cred_id", credId.String())
	c.Set("ms_id", msId.String())
	c.Request, _ = http.NewRequest("GET", "/dummy?mode="+mode, nil)

	expectedCreds := app.Cred{
		CredId:     credId,
		DBName:     dbName,
		Type:       "mongo",
		DBPort:     "27017",
		DBUsername: "testmongo",
		Host:       "localhost",
	}
	expectedMSID := msId
	expectedResult := &app.PrepSaveRestoreResult{
		StatusCode: http.StatusOK,
		Error:      nil,
		Creds:      expectedCreds,
		User:       user,
		MSId:       expectedMSID,
		DBName:     dbName,
		TabColl:    "",
		Mode:       mode,
	}

	var bytesWritten int64 = 54321
	mockHooks := &testutils.MockHooks{
		PrepSaveRestoreFunc: func(args *app.PrepSaveRestoreArgs) *app.PrepSaveRestoreResult {
			return expectedResult
		},
		BackupPostgresFunc: func(args *app.BackupDBArgs) error {
			t.Fatalf("BackupPostgres should not be called in mongo happy path")
			return nil
		},
		BackupMongoFunc: func(args *app.BackupDBArgs) error {
			if args.Creds.Type != "mongo" {
				t.Fatalf("BackupMongo called with wrong type: %s", args.Creds.Type)
			}
			*args.BytesWritten = bytesWritten
			return nil
		},
	}

	appInstance := &app.App{}
	appInstance.Log = testutils.CreateTestLogger()
	appInstance.Hooks = mockHooks

	appInstance.BackupDB(c)

	require.Equal(t, http.StatusCreated, w.Code)
	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Equal(t, resp["message"], "[mydb] mongo db saved")
	require.Equal(t, float64(bytesWritten), resp["no_of_bytes"])
	require.NotEmpty(t, resp["save_id"])
}

// -------------------- ERROR AND EDGE CASE TESTS --------------------

func TestBackupDB_Error_PrepSaveRestore(t *testing.T) {
	user := testutils.CreateTestUserBasic("erruser")
	c, w := testutils.CreateGinContextWithUser(user)

	dbName := "faildb"
	tabName := "failtable"
	mode := "schema"
	msId := uuid.New()
	credId := uuid.New()
	c.Params = []gin.Param{
		{Key: "db", Value: dbName},
		{Key: "tab", Value: tabName},
		{Key: "cred_id", Value: credId.String()},
		{Key: "ms_id", Value: msId.String()},
	}
	c.Set("cred_id", credId.String())
	c.Set("ms_id", msId.String())
	c.Request, _ = http.NewRequest("GET", "/dummy?mode="+mode, nil)

	mockHooks := &testutils.MockHooks{
		PrepSaveRestoreFunc: func(args *app.PrepSaveRestoreArgs) *app.PrepSaveRestoreResult {
			return &app.PrepSaveRestoreResult{
				StatusCode: http.StatusBadRequest,
				Error:      errors.New("prep failed!"),
			}
		},
		BackupPostgresFunc: func(args *app.BackupDBArgs) error {
			t.Fatalf("BackupPostgres should not be called on PrepSaveRestore error")
			return nil
		},
		BackupMongoFunc: func(args *app.BackupDBArgs) error {
			t.Fatalf("BackupMongo should not be called on PrepSaveRestore error")
			return nil
		},
	}

	appInstance := &app.App{}
	appInstance.Log = testutils.CreateTestLogger()
	appInstance.Hooks = mockHooks

	appInstance.BackupDB(c)

	require.Equal(t, http.StatusBadRequest, w.Code)
	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Equal(t, "prep failed!", resp["message"])
}

func TestBackupDB_Error_BackupPostgres(t *testing.T) {
	user := testutils.CreateTestUserBasic("erruser")
	c, w := testutils.CreateGinContextWithUser(user)

	dbName := "mydb"
	tabName := "mytable"
	mode := "schema"
	msId := uuid.New()
	credId := uuid.New()
	c.Params = []gin.Param{
		{Key: "db", Value: dbName},
		{Key: "tab", Value: tabName},
		{Key: "cred_id", Value: credId.String()},
		{Key: "ms_id", Value: msId.String()},
	}
	c.Set("cred_id", credId.String())
	c.Set("ms_id", msId.String())
	c.Request, _ = http.NewRequest("GET", "/dummy?mode="+mode, nil)

	expectedCreds := app.Cred{
		CredId:     credId,
		DBName:     dbName,
		Type:       "postgres",
		DBPort:     "5432",
		DBUsername: "testuser",
		Host:       "localhost",
	}
	expectedResult := &app.PrepSaveRestoreResult{
		StatusCode: http.StatusOK,
		Error:      nil,
		Creds:      expectedCreds,
		User:       user,
		MSId:       msId,
		DBName:     dbName,
		TabColl:    tabName,
		Mode:       mode,
	}

	mockHooks := &testutils.MockHooks{
		PrepSaveRestoreFunc: func(args *app.PrepSaveRestoreArgs) *app.PrepSaveRestoreResult {
			return expectedResult
		},
		BackupPostgresFunc: func(args *app.BackupDBArgs) error {
			return errors.New("backup failed!")
		},
		BackupMongoFunc: func(args *app.BackupDBArgs) error {
			t.Fatalf("BackupMongo should not be called in postgres error path")
			return nil
		},
	}

	appInstance := &app.App{}
	appInstance.Log = testutils.CreateTestLogger()
	appInstance.Hooks = mockHooks

	appInstance.BackupDB(c)

	require.Equal(t, http.StatusInternalServerError, w.Code)
	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Contains(t, resp["message"], "Something went pop when backing up Postgres")
}

func TestBackupDB_Error_BackupMongo(t *testing.T) {
	user := testutils.CreateTestUserBasic("erruser")
	c, w := testutils.CreateGinContextWithUser(user)

	dbName := "mydb"
	tabName := "mycollection"
	mode := "all"
	msId := uuid.New()
	credId := uuid.New()
	c.Params = []gin.Param{
		{Key: "db", Value: dbName},
		{Key: "tab", Value: tabName},
		{Key: "cred_id", Value: credId.String()},
		{Key: "ms_id", Value: msId.String()},
	}
	c.Set("cred_id", credId.String())
	c.Set("ms_id", msId.String())
	c.Request, _ = http.NewRequest("GET", "/dummy?mode="+mode, nil)

	expectedCreds := app.Cred{
		CredId:     credId,
		DBName:     dbName,
		Type:       "mongo",
		DBPort:     "27017",
		DBUsername: "testmongo",
		Host:       "localhost",
	}
	expectedResult := &app.PrepSaveRestoreResult{
		StatusCode: http.StatusOK,
		Error:      nil,
		Creds:      expectedCreds,
		User:       user,
		MSId:       msId,
		DBName:     dbName,
		TabColl:    tabName,
		Mode:       mode,
	}

	mockHooks := &testutils.MockHooks{
		PrepSaveRestoreFunc: func(args *app.PrepSaveRestoreArgs) *app.PrepSaveRestoreResult {
			return expectedResult
		},
		BackupPostgresFunc: func(args *app.BackupDBArgs) error {
			t.Fatalf("BackupPostgres should not be called in mongo error path")
			return nil
		},
		BackupMongoFunc: func(args *app.BackupDBArgs) error {
			return errors.New("mongo backup failed!")
		},
	}

	appInstance := &app.App{}
	appInstance.Log = testutils.CreateTestLogger()
	appInstance.Hooks = mockHooks

	appInstance.BackupDB(c)

	require.Equal(t, http.StatusInternalServerError, w.Code)
	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Contains(t, resp["message"], "Something went pop when backing up MongoDB")
}

func TestBackupDB_UnprocessableEntity_UnknownType(t *testing.T) {
	user := testutils.CreateTestUserBasic("unknownuser")
	c, w := testutils.CreateGinContextWithUser(user)

	dbName := "unknowndb"
	tabName := "unknowntab"
	mode := "all"
	msId := uuid.New()
	credId := uuid.New()
	c.Params = []gin.Param{
		{Key: "db", Value: dbName},
		{Key: "tab", Value: tabName},
		{Key: "cred_id", Value: credId.String()},
		{Key: "ms_id", Value: msId.String()},
	}
	c.Set("cred_id", credId.String())
	c.Set("ms_id", msId.String())
	c.Request, _ = http.NewRequest("GET", "/dummy?mode="+mode, nil)

	expectedCreds := app.Cred{
		CredId:     credId,
		DBName:     dbName,
		Type:       "unknown",
		DBPort:     "1234",
		DBUsername: "unknownuser",
		Host:       "nowhere",
	}
	expectedResult := &app.PrepSaveRestoreResult{
		StatusCode: http.StatusOK,
		Error:      nil,
		Creds:      expectedCreds,
		User:       user,
		MSId:       msId,
		DBName:     dbName,
		TabColl:    tabName,
		Mode:       mode,
	}

	mockHooks := &testutils.MockHooks{
		PrepSaveRestoreFunc: func(args *app.PrepSaveRestoreArgs) *app.PrepSaveRestoreResult {
			return expectedResult
		},
		BackupPostgresFunc: func(args *app.BackupDBArgs) error {
			t.Fatalf("BackupPostgres should not be called for unknown type")
			return nil
		},
		BackupMongoFunc: func(args *app.BackupDBArgs) error {
			t.Fatalf("BackupMongo should not be called for unknown type")
			return nil
		},
	}

	appInstance := &app.App{}
	appInstance.Log = testutils.CreateTestLogger()
	appInstance.Hooks = mockHooks

	appInstance.BackupDB(c)

	require.Equal(t, http.StatusUnprocessableEntity, w.Code)
	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Equal(t, "Something's not right", resp["message"])
}
