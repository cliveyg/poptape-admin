package unit

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"gorm.io/gorm"
)

// --- Happy path: creds exist ---
func TestListAllCreds_HappyPath(t *testing.T) {
	a, db := testutils.SetupTestAppWithSQLite()
	db.Exec("DELETE FROM creds")

	cred := app.Cred{
		DBName:     "testdb",
		Host:       "localhost",
		Type:       "postgres",
		URL:        "postgres://localhost:5432/testdb",
		DBPort:     "5432",
		DBUsername: "admin",
		DBPassword: "realpass",
	}
	assert.NoError(t, db.Create(&cred).Error)

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
}

// --- No creds in DB: should return 404 with correct message ---
func TestListAllCreds_NoCreds(t *testing.T) {
	a, db := testutils.SetupTestAppWithSQLite()
	db.Exec("DELETE FROM creds")

	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)

	a.ListAllCreds(c)

	assert.Equal(t, http.StatusNotFound, w.Code)
	var resp map[string]string
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "No creds found", resp["message"])
}

// --- DB error: simulate DB failure using MockDB from testutils ---
func TestListAllCreds_DBError(t *testing.T) {
	a, _ := testutils.SetupTestAppWithSQLite()
	mockDB := &testutils.MockDB{}
	mockDB.On("Find", mock.Anything, mock.Anything).Return(&gorm.DB{Error: errors.New("simulated db error")})
	a.DB = mockDB

	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)

	a.ListAllCreds(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	var resp map[string]string
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "Something went nope", resp["message"])
}
