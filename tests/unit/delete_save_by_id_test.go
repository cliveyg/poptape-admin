package unit

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func TestDeleteSaveById_HappyPath(t *testing.T) {
	a, mock, hooks := testutils.SetupAppWithMockDBAndHooks(t)
	mock.MatchExpectationsInOrder(false)

	saveId := uuid.New()
	dbName := "testdb"
	saveRecord := app.SaveRecord{SaveId: saveId, DBName: dbName}

	mock.ExpectQuery(`SELECT \* FROM "save_records" WHERE "save_records"."save_id" = \$1 ORDER BY "save_records"."save_id" LIMIT \$2`).
		WithArgs(saveId, 1).
		WillReturnRows(testutils.SaveRecordRows([]app.SaveRecord{saveRecord}))

	hooks.DeleteGridFSBySaveIDFunc = func(ctx *context.Context, saveIdStr, dbNameStr string) error {
		assert.Equal(t, saveId.String(), saveIdStr)
		assert.Equal(t, dbName, dbNameStr)
		return nil
	}

	mock.ExpectBegin()
	mock.ExpectExec(`DELETE FROM "save_records" WHERE "save_records"."save_id" = \$1`).WithArgs(saveId).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	c.Request = httptest.NewRequest("DELETE", "/admin/save/"+saveId.String(), nil)
	c.Params = gin.Params{{Key: "saveId", Value: saveId.String()}}

	a.DeleteSaveById(c)

	assert.Equal(t, http.StatusOK, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Contains(t, resp["message"], "Save record")
	assert.Contains(t, resp["message"], "mongo data deleted")
}

func TestDeleteSaveById_InvalidUUID(t *testing.T) {
	a, _, _ := testutils.SetupAppWithMockDBAndHooks(t)
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	c.Request = httptest.NewRequest("DELETE", "/admin/save/not-a-uuid", nil)
	c.Params = gin.Params{{Key: "saveId", Value: "not-a-uuid"}}

	a.DeleteSaveById(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, "Bad request", resp["message"])
}

func TestDeleteSaveById_SaveRecordNotFound(t *testing.T) {
	a, mock, _ := testutils.SetupAppWithMockDBAndHooks(t)
	mock.MatchExpectationsInOrder(false)

	saveId := uuid.New()
	mock.ExpectQuery(`SELECT \* FROM "save_records" WHERE "save_records"."save_id" = \$1 ORDER BY "save_records"."save_id" LIMIT \$2`).
		WithArgs(saveId, 1).
		WillReturnRows(testutils.SaveRecordRows([]app.SaveRecord{}))

	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	c.Request = httptest.NewRequest("DELETE", "/admin/save/"+saveId.String(), nil)
	c.Params = gin.Params{{Key: "saveId", Value: saveId.String()}}

	a.DeleteSaveById(c)

	assert.Equal(t, http.StatusNotFound, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, "SaveRecord record not found", resp["message"])
}

func TestDeleteSaveById_DBFirstError(t *testing.T) {
	a, mock, _ := testutils.SetupAppWithMockDBAndHooks(t)
	mock.MatchExpectationsInOrder(false)

	saveId := uuid.New()
	mock.ExpectQuery(`SELECT \* FROM "save_records" WHERE "save_records"."save_id" = \$1 ORDER BY "save_records"."save_id" LIMIT \$2`).
		WithArgs(saveId, 1).
		WillReturnError(errors.New("db exploded"))

	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	c.Request = httptest.NewRequest("DELETE", "/admin/save/"+saveId.String(), nil)
	c.Params = gin.Params{{Key: "saveId", Value: saveId.String()}}

	a.DeleteSaveById(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, "Something went neee", resp["message"])
}

func TestDeleteSaveById_ErrorDeletingMongo(t *testing.T) {
	a, mock, hooks := testutils.SetupAppWithMockDBAndHooks(t)
	mock.MatchExpectationsInOrder(false)

	saveId := uuid.New()
	dbName := "mongoerror"
	saveRecord := app.SaveRecord{SaveId: saveId, DBName: dbName}

	mock.ExpectQuery(`SELECT \* FROM "save_records" WHERE "save_records"."save_id" = \$1 ORDER BY "save_records"."save_id" LIMIT \$2`).
		WithArgs(saveId, 1).
		WillReturnRows(testutils.SaveRecordRows([]app.SaveRecord{saveRecord}))

	hooks.DeleteGridFSBySaveIDFunc = func(ctx *context.Context, saveIdStr, dbNameStr string) error {
		return errors.New("mongo error")
	}

	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	c.Request = httptest.NewRequest("DELETE", "/admin/save/"+saveId.String(), nil)
	c.Params = gin.Params{{Key: "saveId", Value: saveId.String()}}

	a.DeleteSaveById(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, "Something went donk", resp["message"])
}

func TestDeleteSaveById_ErrorDeletingSaveRecord(t *testing.T) {
	a, mock, hooks := testutils.SetupAppWithMockDBAndHooks(t)
	mock.MatchExpectationsInOrder(false)

	saveId := uuid.New()
	dbName := "deleteerror"
	saveRecord := app.SaveRecord{SaveId: saveId, DBName: dbName}

	mock.ExpectQuery(`SELECT \* FROM "save_records" WHERE "save_records"."save_id" = \$1 ORDER BY "save_records"."save_id" LIMIT \$2`).
		WithArgs(saveId, 1).
		WillReturnRows(testutils.SaveRecordRows([]app.SaveRecord{saveRecord}))

	hooks.DeleteGridFSBySaveIDFunc = func(ctx *context.Context, saveIdStr, dbNameStr string) error {
		return nil
	}

	mock.ExpectBegin()
	mock.ExpectExec(`DELETE FROM "save_records" WHERE "save_records"."save_id" = \$1`).WithArgs(saveId).
		WillReturnError(errors.New("delete failed"))
	mock.ExpectRollback()

	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	c.Request = httptest.NewRequest("DELETE", "/admin/save/"+saveId.String(), nil)
	c.Params = gin.Params{{Key: "saveId", Value: saveId.String()}}

	a.DeleteSaveById(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, "Something went splat", resp["message"])
}

func TestDeleteSaveById_DeleteSaveRecordNotFound(t *testing.T) {
	a, mock, hooks := testutils.SetupAppWithMockDBAndHooks(t)
	mock.MatchExpectationsInOrder(false)

	saveId := uuid.New()
	dbName := "notfound"
	saveRecord := app.SaveRecord{SaveId: saveId, DBName: dbName}

	mock.ExpectQuery(`SELECT \* FROM "save_records" WHERE "save_records"."save_id" = \$1 ORDER BY "save_records"."save_id" LIMIT \$2`).
		WithArgs(saveId, 1).
		WillReturnRows(testutils.SaveRecordRows([]app.SaveRecord{saveRecord}))

	hooks.DeleteGridFSBySaveIDFunc = func(ctx *context.Context, saveIdStr, dbNameStr string) error {
		return nil
	}

	mock.ExpectBegin()
	mock.ExpectExec(`DELETE FROM "save_records" WHERE "save_records"."save_id" = \$1`).WithArgs(saveId).
		WillReturnError(gorm.ErrRecordNotFound)
	mock.ExpectRollback()

	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	c.Request = httptest.NewRequest("DELETE", "/admin/save/"+saveId.String(), nil)
	c.Params = gin.Params{{Key: "saveId", Value: saveId.String()}}

	a.DeleteSaveById(c)

	assert.Equal(t, http.StatusNotFound, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, "SaveRecord record not deleted", resp["message"])
}
