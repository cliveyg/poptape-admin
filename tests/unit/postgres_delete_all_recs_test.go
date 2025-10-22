package unit

import (
	"errors"
	"net/http"
	"testing"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/stretchr/testify/assert"
)

func TestPostgresDeleteAllRecs_HappyPath(t *testing.T) {
	a, _, hooks := testutils.SetupAppWithMockDBAndHooks(t)
	hooks.WriteSQLOutFunc = func(args *app.WriteSQLArgs) (any, error) {
		// Simulate ListTables returning "foo\nbar"
		if args.ListTables {
			return "foo\nbar", nil
		}
		// Simulate successful deletion for any table
		return "OK", nil
	}

	cred := &app.Cred{DBName: "somedb"}
	pw := []byte("pw")

	status, err := a.PostgresDeleteAllRecs(cred, &pw)
	assert.Equal(t, http.StatusOK, status)
	assert.NoError(t, err)
}

func TestPostgresDeleteAllRecs_ListTablesError(t *testing.T) {
	a, _, hooks := testutils.SetupAppWithMockDBAndHooks(t)
	hooks.WriteSQLOutFunc = func(args *app.WriteSQLArgs) (any, error) {
		// Simulate error when listing tables
		if args.ListTables {
			return nil, errors.New("fail to list tables")
		}
		return "OK", nil // Shouldn't be called for deletes
	}

	cred := &app.Cred{DBName: "somedb"}
	pw := []byte("pw")

	status, err := a.PostgresDeleteAllRecs(cred, &pw)
	assert.Equal(t, http.StatusInternalServerError, status)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "error listing tables")
}

func TestPostgresDeleteAllRecs_WriteSQLOutError(t *testing.T) {
	a, _, hooks := testutils.SetupAppWithMockDBAndHooks(t)
	hooks.WriteSQLOutFunc = func(args *app.WriteSQLArgs) (any, error) {
		if args.ListTables {
			return "foo\nbar", nil
		}
		if args.SQLStatement == "DELETE FROM foo;" {
			return nil, errors.New("foo delete failed")
		}
		return "OK", nil
	}

	cred := &app.Cred{DBName: "somedb"}
	pw := []byte("pw")

	status, err := a.PostgresDeleteAllRecs(cred, &pw)
	assert.Equal(t, http.StatusInternalServerError, status)
	assert.Error(t, err)
	assert.Equal(t, "foo delete failed", err.Error())
}
