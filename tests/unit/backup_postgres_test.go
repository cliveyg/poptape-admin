package unit

import (
	"errors"
	"io"
	"testing"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/cliveyg/poptape-admin/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/mongo/gridfs"
)

func TestBackupPostgres_HappyPath(t *testing.T) {
	a, _, hooks := testutils.SetupAppWithMockDBAndHooks(t)
	origEncrypt := utils.Encrypt
	origDecrypt := utils.Decrypt
	utils.Encrypt = func(pw, key, nonce []byte) (string, error) { return "mocked_encrypted_password", nil }
	utils.Decrypt = func(val string, key, nonce []byte) ([]byte, error) { return []byte("password"), nil }
	t.Cleanup(func() {
		utils.Encrypt = origEncrypt
		utils.Decrypt = origDecrypt
	})

	a.CommandRunner = &testutils.MockCommandRunner{Cmd: &testutils.MockCmd{}}

	hooks.CreateGridFSUploadStreamFunc = func(db string, filename string, metadata map[string]interface{}) (*gridfs.UploadStream, error) {
		return nil, nil
	}
	hooks.CopyToGridFSFunc = func(uploadStream *gridfs.UploadStream, stdout io.Reader, logPrefix string) (int64, error) {
		return 42, nil
	}
	hooks.SaveWithAutoVersionFunc = func(sr *app.SaveRecord) error {
		return nil
	}

	encPW, err := utils.Encrypt([]byte("password"), nil, nil)
	require.NoError(t, err)
	user := &app.User{
		AdminId:   uuid.New(),
		Username:  "tester",
		Roles:     []app.Role{{Name: "admin"}},
		Active:    true,
		Validated: true,
	}
	cred := &app.Cred{
		CredId:     uuid.New(),
		DBName:     "testdb",
		Host:       "localhost",
		Type:       "postgres",
		URL:        "/testdb",
		DBPort:     "5432",
		DBUsername: "user",
		DBPassword: encPW,
	}
	msID := uuid.New()
	saveID := uuid.New()
	var bytesWritten int64
	args := &app.BackupDBArgs{
		Creds:        cred,
		MsId:         &msID,
		User:         user,
		DB:           "testdb",
		Table:        "table1",
		Mode:         "schema",
		SaveId:       &saveID,
		BytesWritten: &bytesWritten,
	}
	err = a.BackupPostgres(args)
	require.NoError(t, err)
	require.Equal(t, int64(42), bytesWritten)
}

func TestBackupPostgres_CreateGridFSUploadStreamError(t *testing.T) {
	a, _, hooks := testutils.SetupAppWithMockDBAndHooks(t)
	origEncrypt := utils.Encrypt
	origDecrypt := utils.Decrypt
	utils.Encrypt = func(pw, key, nonce []byte) (string, error) { return "mocked_encrypted_password", nil }
	utils.Decrypt = func(val string, key, nonce []byte) ([]byte, error) { return []byte("password"), nil }
	t.Cleanup(func() {
		utils.Encrypt = origEncrypt
		utils.Decrypt = origDecrypt
	})

	a.CommandRunner = &testutils.MockCommandRunner{Cmd: &testutils.MockCmd{}}

	hooks.CreateGridFSUploadStreamFunc = func(db string, filename string, metadata map[string]interface{}) (*gridfs.UploadStream, error) {
		return nil, errors.New("stream error")
	}
	hooks.CopyToGridFSFunc = func(uploadStream *gridfs.UploadStream, stdout io.Reader, logPrefix string) (int64, error) {
		return 0, nil
	}
	hooks.SaveWithAutoVersionFunc = func(sr *app.SaveRecord) error {
		return nil
	}

	encPW, _ := utils.Encrypt([]byte("password"), nil, nil)
	user := &app.User{AdminId: uuid.New(), Username: "tester"}
	cred := &app.Cred{CredId: uuid.New(), DBName: "testdb", Host: "localhost", Type: "postgres", URL: "/testdb", DBPort: "5432", DBUsername: "user", DBPassword: encPW}
	msID := uuid.New()
	saveID := uuid.New()
	var bytesWritten int64
	args := &app.BackupDBArgs{
		Creds:        cred,
		MsId:         &msID,
		User:         user,
		DB:           "testdb",
		Table:        "table1",
		Mode:         "schema",
		SaveId:       &saveID,
		BytesWritten: &bytesWritten,
	}
	err := a.BackupPostgres(args)
	require.Error(t, err)
	require.Contains(t, err.Error(), "stream error")
}

func TestBackupPostgres_CopyToGridFSError(t *testing.T) {
	a, _, hooks := testutils.SetupAppWithMockDBAndHooks(t)
	origEncrypt := utils.Encrypt
	origDecrypt := utils.Decrypt
	utils.Encrypt = func(pw, key, nonce []byte) (string, error) { return "mocked_encrypted_password", nil }
	utils.Decrypt = func(val string, key, nonce []byte) ([]byte, error) { return []byte("password"), nil }
	t.Cleanup(func() {
		utils.Encrypt = origEncrypt
		utils.Decrypt = origDecrypt
	})

	a.CommandRunner = &testutils.MockCommandRunner{Cmd: &testutils.MockCmd{}}

	hooks.CreateGridFSUploadStreamFunc = func(db string, filename string, metadata map[string]interface{}) (*gridfs.UploadStream, error) {
		return nil, nil
	}
	hooks.CopyToGridFSFunc = func(uploadStream *gridfs.UploadStream, stdout io.Reader, logPrefix string) (int64, error) {
		return 0, errors.New("copy error")
	}
	hooks.SaveWithAutoVersionFunc = func(sr *app.SaveRecord) error {
		return nil
	}

	encPW, _ := utils.Encrypt([]byte("password"), nil, nil)
	user := &app.User{AdminId: uuid.New(), Username: "tester"}
	cred := &app.Cred{CredId: uuid.New(), DBName: "testdb", Host: "localhost", Type: "postgres", URL: "/testdb", DBPort: "5432", DBUsername: "user", DBPassword: encPW}
	msID := uuid.New()
	saveID := uuid.New()
	var bytesWritten int64
	args := &app.BackupDBArgs{
		Creds:        cred,
		MsId:         &msID,
		User:         user,
		DB:           "testdb",
		Table:        "table1",
		Mode:         "schema",
		SaveId:       &saveID,
		BytesWritten: &bytesWritten,
	}
	err := a.BackupPostgres(args)
	require.Error(t, err)
	require.Contains(t, err.Error(), "copy error")
}

func TestBackupPostgres_SaveWithAutoVersionError(t *testing.T) {
	a, _, hooks := testutils.SetupAppWithMockDBAndHooks(t)
	origEncrypt := utils.Encrypt
	origDecrypt := utils.Decrypt
	utils.Encrypt = func(pw, key, nonce []byte) (string, error) { return "mocked_encrypted_password", nil }
	utils.Decrypt = func(val string, key, nonce []byte) ([]byte, error) { return []byte("password"), nil }
	t.Cleanup(func() {
		utils.Encrypt = origEncrypt
		utils.Decrypt = origDecrypt
	})

	a.CommandRunner = &testutils.MockCommandRunner{Cmd: &testutils.MockCmd{}}
	hooks.CreateGridFSUploadStreamFunc = func(db string, filename string, metadata map[string]interface{}) (*gridfs.UploadStream, error) {
		return nil, nil
	}
	hooks.CopyToGridFSFunc = func(uploadStream *gridfs.UploadStream, stdout io.Reader, logPrefix string) (int64, error) {
		return 42, nil
	}
	hooks.SaveWithAutoVersionFunc = func(sr *app.SaveRecord) error {
		return errors.New("save error")
	}

	encPW, _ := utils.Encrypt([]byte("password"), nil, nil)
	user := &app.User{AdminId: uuid.New(), Username: "tester", Roles: []app.Role{{Name: "admin"}}, Active: true, Validated: true}
	cred := &app.Cred{CredId: uuid.New(), DBName: "testdb", Host: "localhost", Type: "postgres", URL: "/testdb", DBPort: "5432", DBUsername: "user", DBPassword: encPW}
	msID := uuid.New()
	saveID := uuid.New()
	var bytesWritten int64
	args := &app.BackupDBArgs{
		Creds:        cred,
		MsId:         &msID,
		User:         user,
		DB:           "testdb",
		Table:        "table1",
		Mode:         "schema",
		SaveId:       &saveID,
		BytesWritten: &bytesWritten,
	}
	err := a.BackupPostgres(args)
	require.Error(t, err)
	require.Contains(t, err.Error(), "save error")
}

func TestBackupPostgres_DecryptPasswordError(t *testing.T) {
	a, _, hooks := testutils.SetupAppWithMockDBAndHooks(t)
	origEncrypt := utils.Encrypt
	origDecrypt := utils.Decrypt
	utils.Encrypt = func(pw, key, nonce []byte) (string, error) { return "bad_encrypted_password", nil }
	utils.Decrypt = func(val string, key, nonce []byte) ([]byte, error) { return nil, errors.New("mock decrypt error") }
	t.Cleanup(func() {
		utils.Encrypt = origEncrypt
		utils.Decrypt = origDecrypt
	})

	a.CommandRunner = &testutils.MockCommandRunner{Cmd: &testutils.MockCmd{}}

	var dummy gridfs.UploadStream
	hooks.CreateGridFSUploadStreamFunc = func(db string, filename string, metadata map[string]interface{}) (*gridfs.UploadStream, error) {
		return &dummy, nil
	}
	hooks.CopyToGridFSFunc = func(uploadStream *gridfs.UploadStream, stdout io.Reader, logPrefix string) (int64, error) {
		return 0, nil
	}
	hooks.SaveWithAutoVersionFunc = func(sr *app.SaveRecord) error {
		return nil
	}

	cred := &app.Cred{DBPassword: "bad_encrypted_password"}
	user := &app.User{AdminId: uuid.New(), Username: "tester"}
	msID := uuid.New()
	saveID := uuid.New()
	var bytesWritten int64
	args := &app.BackupDBArgs{
		Creds:        cred,
		MsId:         &msID,
		User:         user,
		DB:           "testdb",
		Table:        "table1",
		Mode:         "schema",
		SaveId:       &saveID,
		BytesWritten: &bytesWritten,
	}
	err := a.BackupPostgres(args)
	require.Error(t, err)
	require.Contains(t, err.Error(), "mock decrypt error")
}
