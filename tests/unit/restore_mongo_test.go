package unit

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/stretchr/testify/require"
)

func TestRestoreMongo_HappyPath(t *testing.T) {
	a := &app.App{}
	a.Log = testutils.CreateTestLogger()
	a.CommandRunner = &testutils.MockCommandRunner{
		Cmd: &testutils.MockCmd{
			Stdout: []byte("success"),
		},
	}
	calledWriteMongoOut := false
	a.Hooks = &testutils.MockHooks{
		WriteMongoOutFunc: func(args *app.WriteMongoArgs) (string, error) {
			calledWriteMongoOut = true
			return "ok", nil
		},
		IOCopyFunc: func(dstWriter io.Writer, srcReader io.Reader) (int64, error) {
			return 42, nil // Simulate successful copy
		},
	}
	pw := []byte("pw")
	save := &app.SaveRecord{
		Mode:  "all",
		Table: "mytable",
	}
	ctx := context.Background()
	args := &app.RestoreDBArgs{
		Save:           save,
		Creds:          &app.Cred{DBUsername: "user", Host: "host", DBPort: "123", DBName: "dbname"},
		Password:       &pw,
		DownloadStream: nil, // Value irrelevant due to IOCopyFunc mock
		MongoContext:   &ctx,
	}
	code, msg := a.RestoreMongo(args)
	require.True(t, calledWriteMongoOut, "WriteMongoOut should be called")
	require.Equal(t, http.StatusOK, code)
	require.Contains(t, msg, "Mongo restore succeeded")
}

func TestRestoreMongo_WriteMongoOutFails(t *testing.T) {
	a := &app.App{}
	a.Log = testutils.CreateTestLogger()
	a.CommandRunner = &testutils.MockCommandRunner{
		Cmd: &testutils.MockCmd{},
	}
	a.Hooks = &testutils.MockHooks{
		WriteMongoOutFunc: func(args *app.WriteMongoArgs) (string, error) {
			return "", errors.New("drop failed")
		},
		IOCopyFunc: func(dstWriter io.Writer, srcReader io.Reader) (int64, error) {
			return 42, nil
		},
	}
	pw := []byte("pw")
	save := &app.SaveRecord{
		Mode:  "all",
		Table: "mytable",
	}
	ctx := context.Background()
	args := &app.RestoreDBArgs{
		Save:           save,
		Creds:          &app.Cred{DBUsername: "user", Host: "host", DBPort: "123", DBName: "dbname"},
		Password:       &pw,
		DownloadStream: nil,
		MongoContext:   &ctx,
	}
	code, msg := a.RestoreMongo(args)
	require.Equal(t, http.StatusInternalServerError, code)
	require.Contains(t, msg, "Failed to drop collection before restore")
}

func TestRestoreMongo_CommandStartFails(t *testing.T) {
	a := &app.App{}
	a.Log = testutils.CreateTestLogger()
	a.CommandRunner = &testutils.MockCommandRunner{
		Cmd: &testutils.MockCmd{StartErr: errors.New("start error")},
	}
	a.Hooks = &testutils.MockHooks{
		WriteMongoOutFunc: func(args *app.WriteMongoArgs) (string, error) {
			return "ok", nil
		},
		IOCopyFunc: func(dstWriter io.Writer, srcReader io.Reader) (int64, error) {
			return 42, nil
		},
	}
	pw := []byte("pw")
	save := &app.SaveRecord{Mode: "all"}
	ctx := context.Background()
	args := &app.RestoreDBArgs{
		Save:           save,
		Creds:          &app.Cred{DBUsername: "user", Host: "host", DBPort: "123", DBName: "dbname"},
		Password:       &pw,
		DownloadStream: nil,
		MongoContext:   &ctx,
	}
	code, msg := a.RestoreMongo(args)
	require.Equal(t, http.StatusInternalServerError, code)
	require.Contains(t, msg, "Error starting mongorestore")
}

func TestRestoreMongo_CommandWaitFails(t *testing.T) {
	a := &app.App{}
	a.Log = testutils.CreateTestLogger()
	a.CommandRunner = &testutils.MockCommandRunner{
		Cmd: &testutils.MockCmd{WaitErr: errors.New("wait error")},
	}
	a.Hooks = &testutils.MockHooks{
		WriteMongoOutFunc: func(args *app.WriteMongoArgs) (string, error) {
			return "ok", nil
		},
		IOCopyFunc: func(dstWriter io.Writer, srcReader io.Reader) (int64, error) {
			return 42, nil
		},
	}
	pw := []byte("pw")
	save := &app.SaveRecord{Mode: "all"}
	ctx := context.Background()
	args := &app.RestoreDBArgs{
		Save:           save,
		Creds:          &app.Cred{DBUsername: "user", Host: "host", DBPort: "123", DBName: "dbname"},
		Password:       &pw,
		DownloadStream: nil,
		MongoContext:   &ctx,
	}
	code, msg := a.RestoreMongo(args)
	require.Equal(t, http.StatusInternalServerError, code)
	require.Contains(t, msg, "mongorestore failed")
}

// --- MISSING TEST 1: cmd.StdinPipe() fails ---
func TestRestoreMongo_StdinPipeFails(t *testing.T) {
	a := &app.App{}
	a.Log = testutils.CreateTestLogger()
	a.CommandRunner = &testutils.MockCommandRunner{
		Cmd: &testutils.MockCmd{StdinPipeErr: errors.New("pipe error")},
	}
	a.Hooks = &testutils.MockHooks{
		WriteMongoOutFunc: func(args *app.WriteMongoArgs) (string, error) {
			return "ok", nil
		},
		IOCopyFunc: func(dstWriter io.Writer, srcReader io.Reader) (int64, error) {
			return 42, nil
		},
	}
	pw := []byte("pw")
	save := &app.SaveRecord{Mode: "all"}
	ctx := context.Background()
	args := &app.RestoreDBArgs{
		Save:           save,
		Creds:          &app.Cred{DBUsername: "user", Host: "host", DBPort: "123", DBName: "dbname"},
		Password:       &pw,
		DownloadStream: nil,
		MongoContext:   &ctx,
	}
	code, msg := a.RestoreMongo(args)
	require.Equal(t, http.StatusInternalServerError, code)
	require.Contains(t, msg, "Error preparing mongorestore")
}

// --- MISSING TEST 2: IOCopy fails ---
func TestRestoreMongo_IOCopyFails(t *testing.T) {
	a := &app.App{}
	a.Log = testutils.CreateTestLogger()
	a.CommandRunner = &testutils.MockCommandRunner{
		Cmd: &testutils.MockCmd{},
	}
	a.Hooks = &testutils.MockHooks{
		WriteMongoOutFunc: func(args *app.WriteMongoArgs) (string, error) {
			return "ok", nil
		},
		IOCopyFunc: func(dstWriter io.Writer, srcReader io.Reader) (int64, error) {
			return 0, errors.New("copy error")
		},
	}
	pw := []byte("pw")
	save := &app.SaveRecord{Mode: "all"}
	ctx := context.Background()
	args := &app.RestoreDBArgs{
		Save:           save,
		Creds:          &app.Cred{DBUsername: "user", Host: "host", DBPort: "123", DBName: "dbname"},
		Password:       &pw,
		DownloadStream: nil,
		MongoContext:   &ctx,
	}
	code, msg := a.RestoreMongo(args)
	require.Equal(t, http.StatusInternalServerError, code)
	require.Contains(t, msg, "Error streaming to mongorestore")
}
