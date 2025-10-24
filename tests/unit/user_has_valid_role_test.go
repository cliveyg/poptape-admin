package unit

import (
	"testing"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/stretchr/testify/assert"
)

func TestUserHasValidRole_SingleValidRole(t *testing.T) {
	a := &app.App{}

	roles := []app.Role{
		{Name: "admin"},
	}
	allowed := []string{"admin", "super"}

	ok := a.UserHasValidRole(roles, allowed)
	assert.True(t, ok)
}

func TestUserHasValidRole_MultipleRoles_OneValid(t *testing.T) {
	a := &app.App{}

	roles := []app.Role{
		{Name: "user"},
		{Name: "admin"},
		{Name: "guest"},
	}
	allowed := []string{"admin", "super"}

	ok := a.UserHasValidRole(roles, allowed)
	assert.True(t, ok)
}

func TestUserHasValidRole_NoValidRole(t *testing.T) {
	a := &app.App{}

	roles := []app.Role{
		{Name: "guest"},
		{Name: "user"},
	}
	allowed := []string{"admin", "super"}

	ok := a.UserHasValidRole(roles, allowed)
	assert.False(t, ok)
}

func TestUserHasValidRole_EmptyRoles(t *testing.T) {
	a := &app.App{}
	roles := []app.Role{}
	allowed := []string{"admin", "super"}

	ok := a.UserHasValidRole(roles, allowed)
	assert.False(t, ok)
}

func TestUserHasValidRole_EmptyAllowedRoles(t *testing.T) {
	a := &app.App{}
	roles := []app.Role{
		{Name: "admin"},
	}
	allowed := []string{}

	ok := a.UserHasValidRole(roles, allowed)
	assert.False(t, ok)
}

func TestUserHasValidRole_BothEmpty(t *testing.T) {
	a := &app.App{}
	roles := []app.Role{}
	allowed := []string{}

	ok := a.UserHasValidRole(roles, allowed)
	assert.False(t, ok)
}
