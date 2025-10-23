package unit

import (
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestRestorePostgres_SchemaMode_DropTable_HappyPath(t *testing.T) {
	a, _, hooks := testutils.SetupAppWithMockDBAndHooks(t)
	a.CommandRunner = &testutils.MockCommandRunner{Cmd: &testutils.MockCmd{}}
	hooks.WriteSQLOutFunc = func(args *app.WriteSQLArgs) (any, error) { return nil, nil }
	hooks.IOCopyFunc = func(dst io.Writer, src io.Reader) (int64, error) { return 42, nil }
	pw := []byte("pw")
	args := &app.RestoreDBArgs{
		Save:     &app.SaveRecord{Mode: "schema", Table: "mytable"},
		Creds:    &app.Cred{DBUsername: "user", DBPassword: "password", DBPort: "5432", DBName: "testdb", Host: "localhost", Type: "postgres", CredId: uuid.New()},
		Password: &pw,
	}
	sc, msg := a.RestorePostgres(args)
	require.Equal(t, http.StatusOK, sc)
	require.Contains(t, msg, "Postgres restore succeeded")
}

func TestRestorePostgres_SchemaMode_DropTable_WriteSQLOutFails(t *testing.T) {
	a, _, hooks := testutils.SetupAppWithMockDBAndHooks(t)
	a.CommandRunner = &testutils.MockCommandRunner{Cmd: &testutils.MockCmd{}}
	hooks.WriteSQLOutFunc = func(args *app.WriteSQLArgs) (any, error) { return nil, errors.New("sqlout error") }
	hooks.IOCopyFunc = func(dst io.Writer, src io.Reader) (int64, error) { return 42, nil }
	pw := []byte("pw")
	args := &app.RestoreDBArgs{
		Save:     &app.SaveRecord{Mode: "schema", Table: "mytable"},
		Creds:    &app.Cred{DBUsername: "user", DBPassword: "password", DBPort: "5432", DBName: "testdb", Host: "localhost", Type: "postgres", CredId: uuid.New()},
		Password: &pw,
	}
	sc, msg := a.RestorePostgres(args)
	require.Equal(t, http.StatusInternalServerError, sc)
	require.Contains(t, msg, "plink")
}

func TestRestorePostgres_SchemaMode_DropAllTables_HappyPath(t *testing.T) {
	a, _, hooks := testutils.SetupAppWithMockDBAndHooks(t)
	a.CommandRunner = &testutils.MockCommandRunner{Cmd: &testutils.MockCmd{}}
	tableList := "foo\nbar"
	calls := []string{}
	hooks.WriteSQLOutFunc = func(args *app.WriteSQLArgs) (any, error) {
		if args.ListTables {
			return tableList, nil
		}
		calls = append(calls, args.SQLStatement)
		return nil, nil
	}
	hooks.IOCopyFunc = func(dst io.Writer, src io.Reader) (int64, error) { return 42, nil }
	pw := []byte("pw")
	args := &app.RestoreDBArgs{
		Save:     &app.SaveRecord{Mode: "schema"},
		Creds:    &app.Cred{DBUsername: "user", DBPassword: "password", DBPort: "5432", DBName: "testdb", Host: "localhost", Type: "postgres", CredId: uuid.New()},
		Password: &pw,
	}
	sc, msg := a.RestorePostgres(args)
	require.Equal(t, http.StatusOK, sc)
	require.Contains(t, msg, "Postgres restore succeeded")
	require.Contains(t, calls, "DROP TABLE foo CASCADE")
	require.Contains(t, calls, "DROP TABLE bar CASCADE")
}

func TestRestorePostgres_SchemaMode_ListTablesFails(t *testing.T) {
	a, _, hooks := testutils.SetupAppWithMockDBAndHooks(t)
	a.CommandRunner = &testutils.MockCommandRunner{Cmd: &testutils.MockCmd{}}
	hooks.WriteSQLOutFunc = func(args *app.WriteSQLArgs) (any, error) {
		if args.ListTables {
			return nil, errors.New("list error")
		}
		return nil, nil
	}
	hooks.IOCopyFunc = func(dst io.Writer, src io.Reader) (int64, error) { return 42, nil }
	pw := []byte("pw")
	args := &app.RestoreDBArgs{
		Save:     &app.SaveRecord{Mode: "schema"},
		Creds:    &app.Cred{DBUsername: "user", DBPassword: "password", DBPort: "5432", DBName: "testdb", Host: "localhost", Type: "postgres", CredId: uuid.New()},
		Password: &pw,
	}
	sc, msg := a.RestorePostgres(args)
	require.Equal(t, http.StatusInternalServerError, sc)
	require.Contains(t, msg, "scree")
}

func TestRestorePostgres_SchemaMode_DropAllTables_WriteSQLOutFails(t *testing.T) {
	a, _, hooks := testutils.SetupAppWithMockDBAndHooks(t)
	a.CommandRunner = &testutils.MockCommandRunner{Cmd: &testutils.MockCmd{}}
	tableList := "foo\nbar"
	hooks.WriteSQLOutFunc = func(args *app.WriteSQLArgs) (any, error) {
		if args.ListTables {
			return tableList, nil
		}
		if args.SQLStatement == "DROP TABLE bar CASCADE" {
			return nil, errors.New("fail bar")
		}
		return nil, nil
	}
	hooks.IOCopyFunc = func(dst io.Writer, src io.Reader) (int64, error) { return 42, nil }
	pw := []byte("pw")
	args := &app.RestoreDBArgs{
		Save:     &app.SaveRecord{Mode: "schema"},
		Creds:    &app.Cred{DBUsername: "user", DBPassword: "password", DBPort: "5432", DBName: "testdb", Host: "localhost", Type: "postgres", CredId: uuid.New()},
		Password: &pw,
	}
	sc, msg := a.RestorePostgres(args)
	require.Equal(t, http.StatusInternalServerError, sc)
	require.Contains(t, msg, "twang")
}

func TestRestorePostgres_DataMode_DeleteTable_HappyPath(t *testing.T) {
	a, _, hooks := testutils.SetupAppWithMockDBAndHooks(t)
	a.CommandRunner = &testutils.MockCommandRunner{Cmd: &testutils.MockCmd{}}
	hooks.WriteSQLOutFunc = func(args *app.WriteSQLArgs) (any, error) { return nil, nil }
	hooks.IOCopyFunc = func(dst io.Writer, src io.Reader) (int64, error) { return 42, nil }
	pw := []byte("pw")
	args := &app.RestoreDBArgs{
		Save:     &app.SaveRecord{Mode: "data", Table: "mytable"},
		Creds:    &app.Cred{DBUsername: "user", DBPassword: "password", DBPort: "5432", DBName: "testdb", Host: "localhost", Type: "postgres", CredId: uuid.New()},
		Password: &pw,
	}
	sc, msg := a.RestorePostgres(args)
	require.Equal(t, http.StatusOK, sc)
	require.Contains(t, msg, "Postgres restore succeeded")
}

func TestRestorePostgres_DataMode_DeleteTable_WriteSQLOutFails(t *testing.T) {
	a, _, hooks := testutils.SetupAppWithMockDBAndHooks(t)
	a.CommandRunner = &testutils.MockCommandRunner{Cmd: &testutils.MockCmd{}}
	hooks.WriteSQLOutFunc = func(args *app.WriteSQLArgs) (any, error) { return nil, errors.New("delete error") }
	hooks.IOCopyFunc = func(dst io.Writer, src io.Reader) (int64, error) { return 42, nil }
	pw := []byte("pw")
	args := &app.RestoreDBArgs{
		Save:     &app.SaveRecord{Mode: "data", Table: "mytable"},
		Creds:    &app.Cred{DBUsername: "user", DBPassword: "password", DBPort: "5432", DBName: "testdb", Host: "localhost", Type: "postgres", CredId: uuid.New()},
		Password: &pw,
	}
	sc, msg := a.RestorePostgres(args)
	require.Equal(t, http.StatusInternalServerError, sc)
	require.Contains(t, msg, "kerplunk")
}

func TestRestorePostgres_DataMode_DeleteAllTables_PostgresDeleteAllRecsFails(t *testing.T) {
	a, _, hooks := testutils.SetupAppWithMockDBAndHooks(t)
	a.CommandRunner = &testutils.MockCommandRunner{Cmd: &testutils.MockCmd{}}
	hooks.PostgresDeleteAllRecsFunc = func(crd *app.Cred, pw *[]byte) (int, error) {
		return http.StatusInternalServerError, errors.New("delete all error")
	}
	hooks.WriteSQLOutFunc = func(args *app.WriteSQLArgs) (any, error) {
		if args.ListTables {
			return "foo\nbar", nil
		}
		return nil, nil
	}
	hooks.IOCopyFunc = func(dst io.Writer, src io.Reader) (int64, error) { return 42, nil }
	pw := []byte("pw")
	args := &app.RestoreDBArgs{
		Save:     &app.SaveRecord{Mode: "data"},
		Creds:    &app.Cred{DBUsername: "user", DBPassword: "password", DBPort: "5432", DBName: "testdb", Host: "localhost", Type: "postgres", CredId: uuid.New()},
		Password: &pw,
	}
	sc, msg := a.RestorePostgres(args)
	require.Equal(t, http.StatusInternalServerError, sc)
	require.Contains(t, msg, "splat")
}

func TestRestorePostgres_StdinPipeFails(t *testing.T) {
	a, _, hooks := testutils.SetupAppWithMockDBAndHooks(t)
	a.CommandRunner = &testutils.MockCommandRunner{Cmd: &testutils.MockCmd{StdinPipeErr: errors.New("pipe error")}}
	hooks.WriteSQLOutFunc = func(args *app.WriteSQLArgs) (any, error) { return nil, nil }
	hooks.IOCopyFunc = func(dst io.Writer, src io.Reader) (int64, error) { return 42, nil }
	pw := []byte("pw")
	args := &app.RestoreDBArgs{
		Save:     &app.SaveRecord{Mode: "schema", Table: "mytable"},
		Creds:    &app.Cred{DBUsername: "user", DBPassword: "password", DBPort: "5432", DBName: "testdb", Host: "localhost", Type: "postgres", CredId: uuid.New()},
		Password: &pw,
	}
	sc, msg := a.RestorePostgres(args)
	require.Equal(t, http.StatusInternalServerError, sc)
	require.Contains(t, msg, "donk")
}

func TestRestorePostgres_CmdStartFails(t *testing.T) {
	a, _, hooks := testutils.SetupAppWithMockDBAndHooks(t)
	a.CommandRunner = &testutils.MockCommandRunner{Cmd: &testutils.MockCmd{StartErr: errors.New("start error")}}
	hooks.WriteSQLOutFunc = func(args *app.WriteSQLArgs) (any, error) { return nil, nil }
	hooks.IOCopyFunc = func(dst io.Writer, src io.Reader) (int64, error) { return 42, nil }
	pw := []byte("pw")
	args := &app.RestoreDBArgs{
		Save:     &app.SaveRecord{Mode: "schema", Table: "mytable"},
		Creds:    &app.Cred{DBUsername: "user", DBPassword: "password", DBPort: "5432", DBName: "testdb", Host: "localhost", Type: "postgres", CredId: uuid.New()},
		Password: &pw,
	}
	sc, msg := a.RestorePostgres(args)
	require.Equal(t, http.StatusInternalServerError, sc)
	require.Contains(t, msg, "twong")
}

func TestRestorePostgres_IOCopyFails(t *testing.T) {
	a, _, hooks := testutils.SetupAppWithMockDBAndHooks(t)
	a.CommandRunner = &testutils.MockCommandRunner{Cmd: &testutils.MockCmd{}}
	hooks.WriteSQLOutFunc = func(args *app.WriteSQLArgs) (any, error) { return nil, nil }
	hooks.IOCopyFunc = func(dst io.Writer, src io.Reader) (int64, error) { return 0, errors.New("copy error") }
	pw := []byte("pw")
	args := &app.RestoreDBArgs{
		Save:     &app.SaveRecord{Mode: "schema", Table: "mytable"},
		Creds:    &app.Cred{DBUsername: "user", DBPassword: "password", DBPort: "5432", DBName: "testdb", Host: "localhost", Type: "postgres", CredId: uuid.New()},
		Password: &pw,
	}
	sc, msg := a.RestorePostgres(args)
	require.Equal(t, http.StatusInternalServerError, sc)
	require.Contains(t, msg, "splash")
}

func TestRestorePostgres_CmdWaitFails(t *testing.T) {
	a, _, hooks := testutils.SetupAppWithMockDBAndHooks(t)
	a.CommandRunner = &testutils.MockCommandRunner{Cmd: &testutils.MockCmd{WaitErr: errors.New("wait error")}}
	hooks.WriteSQLOutFunc = func(args *app.WriteSQLArgs) (any, error) { return nil, nil }
	hooks.IOCopyFunc = func(dst io.Writer, src io.Reader) (int64, error) { return 42, nil }
	pw := []byte("pw")
	args := &app.RestoreDBArgs{
		Save:     &app.SaveRecord{Mode: "schema", Table: "mytable"},
		Creds:    &app.Cred{DBUsername: "user", DBPassword: "password", DBPort: "5432", DBName: "testdb", Host: "localhost", Type: "postgres", CredId: uuid.New()},
		Password: &pw,
	}
	sc, msg := a.RestorePostgres(args)
	require.Equal(t, http.StatusInternalServerError, sc)
	require.Contains(t, msg, "psql failed")
}
