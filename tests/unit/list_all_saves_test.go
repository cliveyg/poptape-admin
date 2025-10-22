package unit

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestListAllSaves_MetaInvalid_Returns400(t *testing.T) {
	a, _, _ := testutils.SetupTestAppWithSQLMock(t)
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	c.Request = httptest.NewRequest("GET", "/", nil)
	c.Request.URL.RawQuery = "meta=invalid"
	a.ListAllSaves(c)
	require.Equal(t, http.StatusBadRequest, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	require.Equal(t, "Invalid meta value", resp["message"])
}

func TestListAllSaves_HappyPath_Returns200WithSaves(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)

	saves := []app.SaveRecord{
		{
			SaveId:         uuid.New(),
			MicroserviceId: uuid.New(),
			CredId:         uuid.New(),
			DBName:         "dbA",
			Table:          "tableA",
			SavedBy:        "tester",
			Version:        1,
			Dataset:        0,
			Mode:           "all",
			Valid:          true,
			Type:           "postgres",
			Size:           123,
		},
		{
			SaveId:         uuid.New(),
			MicroserviceId: uuid.New(),
			CredId:         uuid.New(),
			DBName:         "dbB",
			Table:          "tableB",
			SavedBy:        "tester2",
			Version:        2,
			Dataset:        1,
			Mode:           "all",
			Valid:          false,
			Type:           "mongo",
			Size:           456,
		},
	}

	rows := testutils.SaveRecordRows(saves)
	mock.ExpectQuery(`SELECT \* FROM "save_records" ORDER BY db_name asc, version desc`).WillReturnRows(rows)

	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	c.Request = httptest.NewRequest("GET", "/", nil)
	a.ListAllSaves(c)
	require.Equal(t, http.StatusOK, w.Code)
	gotSaves, gotCount := testutils.ListAllSavesExtractSavesList(t, w.Body.Bytes())
	require.Equal(t, len(saves), gotCount)
	require.Len(t, gotSaves, len(saves))
	for i := range saves {
		require.Equal(t, saves[i].SaveId, gotSaves[i].SaveId)
		require.Equal(t, saves[i].DBName, gotSaves[i].DBName)
		require.Equal(t, saves[i].Table, gotSaves[i].Table)
		require.Equal(t, saves[i].SavedBy, gotSaves[i].SavedBy)
		require.Equal(t, saves[i].Version, gotSaves[i].Version)
		require.Equal(t, saves[i].Dataset, gotSaves[i].Dataset)
		require.Equal(t, saves[i].Mode, gotSaves[i].Mode)
		require.Equal(t, saves[i].Valid, gotSaves[i].Valid)
		require.Equal(t, saves[i].Type, gotSaves[i].Type)
		require.Equal(t, saves[i].Size, gotSaves[i].Size)
	}
}

func TestListAllSaves_DBErrorNotFound_Returns404(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)

	mock.ExpectQuery(`SELECT \* FROM "save_records" ORDER BY db_name asc, version desc`).
		WillReturnError(gorm.ErrRecordNotFound)

	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	c.Request = httptest.NewRequest("GET", "/", nil)
	a.ListAllSaves(c)
	require.Equal(t, http.StatusNotFound, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	require.Equal(t, "No save records found", resp["message"])
}

func TestListAllSaves_DBErrorOther_Returns500(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)

	mock.ExpectQuery(`SELECT \* FROM "save_records" ORDER BY db_name asc, version desc`).
		WillReturnError(errors.New("something bad happened"))

	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	c.Request = httptest.NewRequest("GET", "/", nil)
	a.ListAllSaves(c)
	require.Equal(t, http.StatusInternalServerError, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	require.Contains(t, resp["message"], "Something went neee")
}

func TestListAllSaves_ZeroRows_Returns404(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	mock.MatchExpectationsInOrder(false)
	rows := testutils.SaveRecordRows([]app.SaveRecord{})
	mock.ExpectQuery(`SELECT \* FROM "save_records" ORDER BY db_name asc, version desc`).WillReturnRows(rows)

	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	c.Request = httptest.NewRequest("GET", "/", nil)
	a.ListAllSaves(c)
	require.Equal(t, http.StatusNotFound, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	require.Equal(t, "No save records found", resp["message"])
}
