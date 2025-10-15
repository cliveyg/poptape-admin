package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/rs/zerolog"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func setupLogger() *zerolog.Logger {
	var logWriter = os.Stdout
	cw := zerolog.ConsoleWriter{Out: logWriter, NoColor: true, TimeFormat: time.RFC3339}
	cw.FormatLevel = func(i interface{}) string {
		return strings.ToUpper(fmt.Sprintf("[ %-6s]", i))
	}
	cw.TimeFormat = "[" + time.RFC3339 + "] - "
	cw.FormatCaller = func(i interface{}) string {
		str, _ := i.(string)
		return fmt.Sprintf("['%s']", str)
	}
	cw.PartsOrder = []string{
		zerolog.LevelFieldName,
		zerolog.TimestampFieldName,
		zerolog.MessageFieldName,
		zerolog.CallerFieldName,
	}

	logger := zerolog.New(cw).With().Timestamp().Caller().Logger()
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	return &logger
}

func setupTestApp(t *testing.T) *app.App {
	a := &app.App{}
	a.Log = setupLogger()
	a.CommandRunner = &app.RealCommandRunner{}
	a.InitialiseApp()
	return a
}

func loginAndGetToken(t *testing.T, testApp *app.App, username, password string) string {
	loginReq := map[string]string{
		"username": username,
		"password": password,
	}
	body, _ := json.Marshal(loginReq)
	req, err := http.NewRequest("POST", "/admin/login", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	testApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, "login should return 200")

	var out struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&out))
	require.NotEmpty(t, out.Token)
	return out.Token
}

func setUserValidated(t *testing.T, testApp *app.App, username string) {
	result := testApp.DB.Model(&app.User{}).Where("username = ?", username).Update("validated", true)
	require.NoError(t, result.Error)
}

func RandString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[int64(len(letters))*int64(os.Getpid()+i)%int64(len(letters))]
	}
	return string(b)
}

func resetDB(t *testing.T, a *app.App) {
	tables := []string{
		"saverecords",
		"creds",
		"role_cred_ms",
		"users",
		"roles",
		"microservices",
	}

	a.Log.Info().Msg("-=-=-=-=-=-=-=-=-=-=-=-=-= resetDB =-=-=-=-=-=-=-=-=-=-=-=-=-=-")

	for _, table := range tables {
		if a.DB.Migrator().HasTable(table) {
			stmt := fmt.Sprintf("TRUNCATE TABLE %s RESTART IDENTITY CASCADE;", table)
			if err := a.DB.Exec(stmt).Error; err != nil {
				if t != nil {
					t.Fatalf("Failed to truncate table %s: %v", table, err)
				} else {
					panic(fmt.Sprintf("Failed to truncate table %s: %v", table, err))
				}
			}
		}
	}
	a.Log.Debug().Msg("All tables cleared")

	if err := a.CreateRoles(); err != nil {
		if t != nil {
			t.Fatalf("Failed to reseed roles: %v", err)
		} else {
			panic(fmt.Sprintf("Failed to reseed roles: %v", err))
		}
	}
	adminId, err := a.CreateSuperUser()
	if err != nil {
		if t != nil {
			t.Fatalf("Failed to reseed superuser: %v", err)
		} else {
			panic(fmt.Sprintf("Failed to reseed superuser: %v", err))
		}
	}
	if err = a.CreateMicroservices(*adminId); err != nil {
		if t != nil {
			t.Fatalf("Failed to reseed microservices: %v", err)
		} else {
			panic(fmt.Sprintf("Failed to reseed microservices: %v", err))
		}
	}
	a.Log.Debug().Msg("Everything reseeded")
}

func resetMongo(t *testing.T, mongoURI, dbName string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	if err == nil {
		defer client.Disconnect(ctx)
	}
	if err != nil {
		t.Fatalf("resetMongo: failed to connect to mongo: %v", err)
	}
	err = client.Database(dbName).Drop(ctx)
	if err != nil && err != mongo.ErrNilDocument {
		t.Fatalf("resetMongo: failed to drop db %q: %v", dbName, err)
	}
}

// mockCommandRunner implements app.CommandRunner
type mockCommandRunner struct {
	t *testing.T
}

func (m *mockCommandRunner) Command(name string, args ...string) app.Cmd {
	m.t.Helper()
	if name != "pg_dump" {
		m.t.Fatalf("mockCommandRunner: unexpected command %q", name)
	}
	return &mockCmd{t: m.t}
}

// mockCmd implements app.Cmd
type mockCmd struct {
	t *testing.T
}

func (c *mockCmd) Start() error                       { return nil }
func (c *mockCmd) Run() error                         { return nil }
func (c *mockCmd) Wait() error                        { return nil }
func (c *mockCmd) StdoutPipe() (io.ReadCloser, error) { return c.mockFixtureReader(), nil }
func (c *mockCmd) StderrPipe() (io.ReadCloser, error) { return c.mockEmptyReader(), nil }
func (c *mockCmd) StdinPipe() (io.WriteCloser, error) { return &mockWriteCloser{}, nil }
func (c *mockCmd) SetEnv(env []string)                {}
func (c *mockCmd) SetStdout(w io.Writer)              {}
func (c *mockCmd) SetStderr(w io.Writer)              {}
func (c *mockCmd) SetStdin(r io.Reader)               {}

func (c *mockCmd) mockFixtureReader() io.ReadCloser {
	data, err := os.ReadFile("tests/fixtures/reviews.dump")
	if err != nil {
		c.t.Fatalf("mockCmd: failed to read fixture: %v", err)
	}
	return io.NopCloser(bytes.NewReader(data))
}

func (c *mockCmd) mockEmptyReader() io.ReadCloser {
	return io.NopCloser(bytes.NewReader([]byte{}))
}

type mockWriteCloser struct{}

func (m *mockWriteCloser) Write(p []byte) (n int, err error) { return len(p), nil }
func (m *mockWriteCloser) Close() error                      { return nil }
