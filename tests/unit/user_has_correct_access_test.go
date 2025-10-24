package unit

import (
	"errors"
	"github.com/stretchr/testify/mock"
	"net/http"
	"testing"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func TestUserHasCorrectAccess_RecordNotFound(t *testing.T) {
	mockDB := &testutils.MockDB{}
	mockDB.On("First", mock.Anything, mock.Anything).Return(&gorm.DB{Error: gorm.ErrRecordNotFound})

	a := &app.App{
		DB:  mockDB,
		Log: testutils.SetupLogger(),
	}
	svRec := &app.SaveRecord{}
	user := &app.User{}
	code, err := a.UserHasCorrectAccess(svRec, user)
	assert.Equal(t, http.StatusNotFound, code)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "RoleCredMS record not found")
}

func TestUserHasCorrectAccess_DBError(t *testing.T) {
	mockDB := &testutils.MockDB{}
	mockDB.On("First", mock.Anything, mock.Anything).Return(&gorm.DB{Error: errors.New("some db error")})

	a := &app.App{
		DB:  mockDB,
		Log: testutils.SetupLogger(),
	}
	svRec := &app.SaveRecord{}
	user := &app.User{}
	code, err := a.UserHasCorrectAccess(svRec, user)
	assert.Equal(t, http.StatusInternalServerError, code)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Something went boooom")
}

func TestUserHasCorrectAccess_Forbidden(t *testing.T) {
	mockDB := &testutils.MockDB{}
	mockDB.On("First", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		if rcms, ok := args.Get(0).(*app.RoleCredMS); ok {
			rcms.RoleName = "writer"
		}
	}).Return(&gorm.DB{})

	a := &app.App{
		DB:  mockDB,
		Log: testutils.SetupLogger(),
	}
	svRec := &app.SaveRecord{}
	user := &app.User{
		Username: "bob",
		Roles:    []app.Role{{Name: "reader"}}, // "reader" is not in allowed roles ["super", "admin", "writer"]
	}
	code, err := a.UserHasCorrectAccess(svRec, user)
	assert.Equal(t, http.StatusForbidden, code)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Forbidden")
}

func TestUserHasCorrectAccess_Ok(t *testing.T) {
	mockDB := &testutils.MockDB{}
	mockDB.On("First", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		if rcms, ok := args.Get(0).(*app.RoleCredMS); ok {
			rcms.RoleName = "writer"
		}
	}).Return(&gorm.DB{})

	a := &app.App{
		DB:  mockDB,
		Log: testutils.SetupLogger(),
	}
	svRec := &app.SaveRecord{}
	user := &app.User{
		Username: "alice",
		Roles:    []app.Role{{Name: "admin"}}, // "admin" is in allowed roles
	}
	code, err := a.UserHasCorrectAccess(svRec, user)
	assert.Equal(t, http.StatusOK, code)
	assert.NoError(t, err)
}
