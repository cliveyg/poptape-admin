package unit

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// --- Happy path: creds exist ---
func TestListAllCreds_HappyPath(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	credID := uuid.New()
	now := time.Now()

	// Prepare the expected rows for Find(&crds)
	rows := sqlmock.NewRows([]string{
		"cred_id", "db_name", "host", "type", "url", "db_port", "db_username", "db_password", "last_used", "last_used_by", "created_by", "created",
	}).AddRow(credID, "testdb", "localhost", "postgres", "postgres://localhost:5432/testdb", "5432", "admin", "realpass", now, "tester", uuid.New(), now)

	mock.ExpectQuery(`SELECT \* FROM "creds"`).
		WillReturnRows(rows)

	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)

	a.ListAllCreds(c)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Creds []app.Cred `json:"creds"`
	}
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Creds, 1)
	assert.Equal(t, "XXXX", resp.Creds[0].DBPassword)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// --- No creds in DB: should return 404 with correct message ---
func TestListAllCreds_NoCreds(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)

	rows := sqlmock.NewRows([]string{
		"cred_id", "db_name", "host", "type", "url", "db_port", "db_username", "db_password", "last_used", "last_used_by", "created_by", "created",
	})
	mock.ExpectQuery(`SELECT \* FROM "creds"`).
		WillReturnRows(rows)

	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)

	a.ListAllCreds(c)

	assert.Equal(t, http.StatusNotFound, w.Code)
	var resp map[string]string
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "No creds found", resp["message"])
	assert.NoError(t, mock.ExpectationsWereMet())
}

// --- DB error: simulate DB failure ---
func TestListAllCreds_DBError(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)

	mock.ExpectQuery(`SELECT \* FROM "creds"`).
		WillReturnError(errors.New("simulated db error"))

	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)

	a.ListAllCreds(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	var resp map[string]string
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "Something went nope", resp["message"])
	assert.NoError(t, mock.ExpectationsWereMet())
}
