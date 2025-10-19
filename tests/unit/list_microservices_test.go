package unit

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// Helper in testutils: generates sqlmock.Rows for []app.Microservice
// Add to testutils/sqlmock_helpers.go if not present
// func MicroserviceRows(mss []app.Microservice) *sqlmock.Rows

func TestListMicroservices_Success_SQLMock(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)

	adminID := uuid.New()
	user := app.User{
		AdminId:   adminID,
		Username:  "admin",
		Roles:     []app.Role{{Name: "admin"}},
		Active:    true,
		Validated: true,
	}

	msCreated := time.Now()
	ms := app.Microservice{
		MicroserviceId: uuid.New(),
		MSName:         "svc1",
		CreatedBy:      adminID,
		Created:        msCreated,
	}
	microservices := []app.Microservice{ms}

	// Expect GORM query: SELECT * FROM "microservices" ORDER BY ms_name asc
	mock.ExpectQuery(`SELECT \* FROM "microservices" ORDER BY ms_name asc`).
		WillReturnRows(testutils.MicroserviceRows(microservices))

	c, w := testutils.CreateGinContextWithUser(user)
	a.ListMicroservices(c)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Microservices []app.Microservice `json:"microservices"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Len(t, resp.Microservices, 1)
	assert.Equal(t, ms.MicroserviceId, resp.Microservices[0].MicroserviceId)
	assert.Equal(t, ms.MSName, resp.Microservices[0].MSName)
	assert.Equal(t, ms.CreatedBy, resp.Microservices[0].CreatedBy)
	assert.WithinDuration(t, ms.Created, resp.Microservices[0].Created, time.Second)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestListMicroservices_NotFound_SQLMock(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	user := app.User{
		AdminId:   uuid.New(),
		Username:  "admin",
		Roles:     []app.Role{{Name: "admin"}},
		Active:    true,
		Validated: true,
	}

	// Empty result set
	mock.ExpectQuery(`SELECT \* FROM "microservices" ORDER BY ms_name asc`).
		WillReturnRows(testutils.MicroserviceRows([]app.Microservice{}))

	c, w := testutils.CreateGinContextWithUser(user)
	a.ListMicroservices(c)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), `"No microservices found"`)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestListMicroservices_DBError_SQLMock(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	user := app.User{
		AdminId:   uuid.New(),
		Username:  "admin",
		Roles:     []app.Role{{Name: "admin"}},
		Active:    true,
		Validated: true,
	}

	mock.ExpectQuery(`SELECT \* FROM "microservices" ORDER BY ms_name asc`).
		WillReturnError(errors.New("db error"))

	c, w := testutils.CreateGinContextWithUser(user)
	a.ListMicroservices(c)

	// The handler returns 404 and "No microservices found" even on db error
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), `"No microservices found"`)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestListMicroservices_InvalidRole_Still200_SQLMock(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	user := app.User{
		AdminId:   uuid.New(),
		Username:  "basic",
		Roles:     []app.Role{{Name: "basic"}},
		Active:    true,
		Validated: true,
	}

	msCreated := time.Now()
	ms := app.Microservice{
		MicroserviceId: uuid.New(),
		MSName:         "svc1",
		CreatedBy:      user.AdminId,
		Created:        msCreated,
	}
	microservices := []app.Microservice{ms}

	mock.ExpectQuery(`SELECT \* FROM "microservices" ORDER BY ms_name asc`).
		WillReturnRows(testutils.MicroserviceRows(microservices))

	c, w := testutils.CreateGinContextWithUser(user)
	a.ListMicroservices(c)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Microservices []app.Microservice `json:"microservices"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Len(t, resp.Microservices, 1)
	assert.Equal(t, ms.MSName, resp.Microservices[0].MSName)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestListMicroservices_NoUserInContext_SQLMock(t *testing.T) {
	a, _, mock := testutils.SetupTestAppWithSQLMock(t)
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	// Don't set "user"

	// Expect empty result set (idiomatic: simulate no microservices found)
	mock.ExpectQuery(`SELECT \* FROM "microservices" ORDER BY ms_name asc`).
		WillReturnRows(testutils.MicroserviceRows([]app.Microservice{}))

	a.ListMicroservices(c)
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), `"No microservices found"`)
	assert.NoError(t, mock.ExpectationsWereMet())
}
