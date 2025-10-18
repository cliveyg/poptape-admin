package unit

import (
	"net/http"
	"testing"
	"time"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestListMicroservices_Success_SQLite(t *testing.T) {
	a, db := testutils.SetupTestAppWithSQLite()

	adminID := uuid.New()
	user := app.User{
		AdminId:  adminID,
		Username: "admin",
		Roles:    []app.Role{{Name: "admin"}},
		Active:   true,
	}
	db.Create(&user)
	db.Create(&app.Role{Name: "admin"})
	ms := app.Microservice{
		MicroserviceId: uuid.New(),
		MSName:         "svc1",
		CreatedBy:      adminID,
		Created:        time.Now(),
	}
	db.Create(&ms)

	c, w := testutils.CreateGinContextWithUser(user)

	a.ListMicroservices(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"microservices"`)
	assert.Contains(t, w.Body.String(), `"svc1"`)
}

func TestListMicroservices_NotFound_SQLite(t *testing.T) {
	a, db := testutils.SetupTestAppWithSQLite()
	user := app.User{
		AdminId:  uuid.New(),
		Username: "admin",
		Roles:    []app.Role{{Name: "admin"}},
		Active:   true,
	}
	db.Create(&user)
	db.Create(&app.Role{Name: "admin"})

	c, w := testutils.CreateGinContextWithUser(user)

	a.ListMicroservices(c)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), `"No microservices found"`)
}

func TestListMicroservices_DBError_SQLite(t *testing.T) {
	a, db := testutils.SetupTestAppWithSQLite()
	user := app.User{
		AdminId:  uuid.New(),
		Username: "admin",
		Roles:    []app.Role{{Name: "admin"}},
		Active:   true,
	}
	db.Create(&user)
	db.Create(&app.Role{Name: "admin"})

	// Simulate DB error by dropping the table
	_ = db.Migrator().DropTable(&app.Microservice{})

	c, w := testutils.CreateGinContextWithUser(user)

	a.ListMicroservices(c)

	// The handler returns 404 and "No microservices found" even on db error
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), `"No microservices found"`)
}

func TestListMicroservices_InvalidRole_Still200_SQLite(t *testing.T) {
	a, db := testutils.SetupTestAppWithSQLite()
	user := app.User{
		AdminId:  uuid.New(),
		Username: "basic",
		Roles:    []app.Role{{Name: "basic"}},
		Active:   true,
	}
	db.Create(&user)
	db.Create(&app.Role{Name: "basic"})
	ms := app.Microservice{
		MicroserviceId: uuid.New(),
		MSName:         "svc1",
		CreatedBy:      user.AdminId,
		Created:        time.Now(),
	}
	db.Create(&ms)

	c, w := testutils.CreateGinContextWithUser(user)

	a.ListMicroservices(c)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"microservices"`)
	assert.Contains(t, w.Body.String(), `"svc1"`)
}

func TestListMicroservices_NoUserInContext_SQLite(t *testing.T) {
	a, _ := testutils.SetupTestAppWithSQLite()
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	// Don't set "user"

	a.ListMicroservices(c)
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), `"No microservices found"`)
}
