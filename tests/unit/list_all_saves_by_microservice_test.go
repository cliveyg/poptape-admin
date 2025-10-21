package unit

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Happy path: saves found ---
func TestListAllSavesByMicroservice_HappyPath(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)

	msId := uuid.New().String()
	saves := []app.SaveRecord{
		{SaveId: uuid.New(), MicroserviceId: uuid.MustParse(msId), DBName: "db1", Valid: true},
		{SaveId: uuid.New(), MicroserviceId: uuid.MustParse(msId), DBName: "db2", Valid: false},
	}
	mock.ExpectQuery(`SELECT \* FROM "save_records"`).WillReturnRows(testutils.SaveRecordRows(saves))

	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	c.Set("ms_id", msId)
	a.ListAllSavesByMicroservice(c)

	require.Equal(t, http.StatusOK, w.Code)
	out := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, float64(2), out["no_of_saves"])
	assert.Len(t, out["saves"], 2)
}

// --- Happy path: filter valid=true ---
func TestListAllSavesByMicroservice_ValidTrue(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)

	msId := uuid.New().String()
	saves := []app.SaveRecord{
		{SaveId: uuid.New(), MicroserviceId: uuid.MustParse(msId), DBName: "db1", Valid: true},
	}
	mock.ExpectQuery(`SELECT \* FROM "save_records"`).WillReturnRows(testutils.SaveRecordRows(saves))

	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	c.Set("ms_id", msId)
	c.Request = httptest.NewRequest("GET", "/", nil)
	c.Request.URL.RawQuery = "valid=true"
	a.ListAllSavesByMicroservice(c)

	require.Equal(t, http.StatusOK, w.Code)
	out := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, float64(1), out["no_of_saves"])
	assert.Len(t, out["saves"], 1)
}

// --- Happy path: filter valid=false ---
func TestListAllSavesByMicroservice_ValidFalse(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)

	msId := uuid.New().String()
	saves := []app.SaveRecord{
		{SaveId: uuid.New(), MicroserviceId: uuid.MustParse(msId), DBName: "db2", Valid: false},
	}
	mock.ExpectQuery(`SELECT \* FROM "save_records"`).WillReturnRows(testutils.SaveRecordRows(saves))

	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	c.Set("ms_id", msId)
	c.Request = httptest.NewRequest("GET", "/", nil)
	c.Request.URL.RawQuery = "valid=false"
	a.ListAllSavesByMicroservice(c)

	require.Equal(t, http.StatusOK, w.Code)
	out := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, float64(1), out["no_of_saves"])
	assert.Len(t, out["saves"], 1)
}

// --- DB error ---
func TestListAllSavesByMicroservice_DBError(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)

	msId := uuid.New().String()
	mock.ExpectQuery(`SELECT \* FROM "save_records"`).WillReturnError(errors.New("db failed"))

	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	c.Set("ms_id", msId)
	a.ListAllSavesByMicroservice(c)

	require.Equal(t, http.StatusInternalServerError, w.Code)
	out := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, "Something went nope", out["message"])
}

// --- No saves found ---
func TestListAllSavesByMicroservice_NoSavesFound(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)

	msId := uuid.New().String()
	mock.ExpectQuery(`SELECT \* FROM "save_records"`).WillReturnRows(testutils.SaveRecordRows([]app.SaveRecord{}))

	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	c.Set("ms_id", msId)
	a.ListAllSavesByMicroservice(c)

	require.Equal(t, http.StatusNotFound, w.Code)
	out := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, "No saves found", out["message"])
}

// --- Invalid "valid" param ---
func TestListAllSavesByMicroservice_InvalidValidParam(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)

	msId := uuid.New().String()
	// No DB interaction expected

	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	c.Set("ms_id", msId)
	c.Request = httptest.NewRequest("GET", "/", nil)
	c.Request.URL.RawQuery = "valid=notabool"
	a.ListAllSavesByMicroservice(c)

	require.Equal(t, http.StatusBadRequest, w.Code)
	out := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, "Value of 'valid' querystring is invalid", out["message"])
}

// --- ms_id missing (simulate context error) ---
func TestListAllSavesByMicroservice_MsIdMissing(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)

	// ms_id not set in context
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	// The handler ignores GetUUIDFromParams error, so it proceeds with zero msId
	// Should produce no saves found if DB returns empty

	mock.ExpectQuery(`SELECT \* FROM "save_records"`).WillReturnRows(testutils.SaveRecordRows([]app.SaveRecord{}))
	a.ListAllSavesByMicroservice(c)

	require.Equal(t, http.StatusNotFound, w.Code)
	out := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, "No saves found", out["message"])
}

// --- Edge case: saves with mix of valid/invalid, filter valid=true ---
func TestListAllSavesByMicroservice_MixedValidFilterTrue(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)

	msId := uuid.New().String()
	// Only valid=true should be returned by DB
	saves := []app.SaveRecord{
		{SaveId: uuid.New(), MicroserviceId: uuid.MustParse(msId), DBName: "db1", Valid: true},
	}
	mock.ExpectQuery(`SELECT \* FROM "save_records"`).WillReturnRows(testutils.SaveRecordRows(saves))

	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	c.Set("ms_id", msId)
	c.Request = httptest.NewRequest("GET", "/", nil)
	c.Request.URL.RawQuery = "valid=true"
	a.ListAllSavesByMicroservice(c)

	require.Equal(t, http.StatusOK, w.Code)
	out := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, float64(1), out["no_of_saves"])
	assert.Len(t, out["saves"], 1)
}
