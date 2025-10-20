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

func TestRestoreDB_HappyPath(t *testing.T) {
	user := testutils.CreateTestUserBasic("restoreuser")
	c, w := testutils.CreateGinContextWithUser(user)
	dbName := "mydb"
	tabName := "mytab"
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

	appInstance := &app.App{}
	appInstance.Log = testutils.CreateTestLogger()

	appInstance.Hooks = &testutils.MockHooks{
		PrepSaveRestoreFunc: func(args *app.PrepSaveRestoreArgs) *app.PrepSaveRestoreResult {
			return &app.PrepSaveRestoreResult{
				StatusCode: http.StatusOK,
				Error:      nil,
				MSId:       msId,
				DBName:     dbName,
				TabColl:    tabName,
				Mode:       mode,
			}
		},
	}

	appInstance.RestoreDB(c)

	require.Equal(t, http.StatusTeapot, w.Code)
	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Equal(t, "Moop", resp["message"])
}

func TestRestoreDB_PrepSaveRestoreError(t *testing.T) {
	user := testutils.CreateTestUserBasic("restoreuser")
	c, w := testutils.CreateGinContextWithUser(user)
	dbName := "mydb"
	tabName := "mytab"
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

	appInstance := &app.App{}
	appInstance.Log = testutils.CreateTestLogger()

	appInstance.Hooks = &testutils.MockHooks{
		PrepSaveRestoreFunc: func(args *app.PrepSaveRestoreArgs) *app.PrepSaveRestoreResult {
			return &app.PrepSaveRestoreResult{
				StatusCode: http.StatusBadRequest,
				Error:      errors.New("bad things happened"),
			}
		},
	}

	appInstance.RestoreDB(c)

	require.Equal(t, http.StatusBadRequest, w.Code)
	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Equal(t, "bad things happened", resp["message"])
}

func TestRestoreDB_Forbidden(t *testing.T) {
	user := testutils.CreateTestUserBasic("restoreuser")
	c, w := testutils.CreateGinContextWithUser(user)
	dbName := "mydb"
	tabName := "mytab"
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

	appInstance := &app.App{}
	appInstance.Log = testutils.CreateTestLogger()

	appInstance.Hooks = &testutils.MockHooks{
		PrepSaveRestoreFunc: func(args *app.PrepSaveRestoreArgs) *app.PrepSaveRestoreResult {
			return &app.PrepSaveRestoreResult{
				StatusCode: http.StatusForbidden,
				Error:      errors.New("forbidden"),
			}
		},
	}

	appInstance.RestoreDB(c)
	require.Equal(t, http.StatusForbidden, w.Code)
	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Equal(t, "forbidden", resp["message"])
}

func TestRestoreDB_EmptyPrepSaveRestoreResult(t *testing.T) {
	user := testutils.CreateTestUserBasic("restoreuser")
	c, w := testutils.CreateGinContextWithUser(user)
	dbName := "emptydb"
	tabName := "emptytab"
	mode := "data"
	c.Params = []gin.Param{
		{Key: "db", Value: dbName},
		{Key: "tab", Value: tabName},
	}
	c.Request, _ = http.NewRequest("GET", "/dummy?mode="+mode, nil)

	appInstance := &app.App{}
	appInstance.Log = testutils.CreateTestLogger()

	appInstance.Hooks = &testutils.MockHooks{
		PrepSaveRestoreFunc: func(args *app.PrepSaveRestoreArgs) *app.PrepSaveRestoreResult {
			return &app.PrepSaveRestoreResult{}
		},
	}

	appInstance.RestoreDB(c)
	require.Equal(t, http.StatusTeapot, w.Code)
	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Equal(t, "Moop", resp["message"])
}
