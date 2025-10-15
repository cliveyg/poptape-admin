package testutils

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cliveyg/poptape-admin/app"
)

// MockCommandRunner implements app.CommandRunner and supports both pg_dump and mongodump.
type MockCommandRunner struct {
	T        *testing.T
	Fixtures map[string]string // map command name to fixture filename
}

func (m *MockCommandRunner) Command(name string, args ...string) app.Cmd {
	m.T.Helper()
	fixture, ok := m.Fixtures[name]
	if !ok {
		m.T.Fatalf("MockCommandRunner: unexpected command %q", name)
	}
	return &mockCmd{T: m.T, Fixture: fixture}
}

type mockCmd struct {
	T       *testing.T
	Fixture string
}

func (c *mockCmd) Start() error                       { return nil }
func (c *mockCmd) Run() error                         { return nil }
func (c *mockCmd) Wait() error                        { return nil }
func (c *mockCmd) StdinPipe() (io.WriteCloser, error) { return &mockWriteCloser{}, nil }
func (c *mockCmd) StderrPipe() (io.ReadCloser, error) { return c.mockEmptyReader(), nil }
func (c *mockCmd) SetEnv(env []string)                {}
func (c *mockCmd) SetStdout(w io.Writer)              {}
func (c *mockCmd) SetStderr(w io.Writer)              {}
func (c *mockCmd) SetStdin(r io.Reader)               {}

func (c *mockCmd) StdoutPipe() (io.ReadCloser, error) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		c.T.Fatalf("mockCmd: unable to determine caller for fixture path")
	}
	utilsDir := filepath.Dir(thisFile)
	fixturePath := filepath.Join(utilsDir, "fixtures", c.Fixture)
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		c.T.Fatalf("mockCmd: failed to read fixture %s: %v", fixturePath, err)
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (c *mockCmd) mockEmptyReader() io.ReadCloser {
	return io.NopCloser(bytes.NewReader([]byte{}))
}

type mockWriteCloser struct{}

func (m *mockWriteCloser) Write(p []byte) (n int, err error) { return len(p), nil }
func (m *mockWriteCloser) Close() error                      { return nil }
