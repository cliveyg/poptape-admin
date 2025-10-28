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

// MockCmd is a fully controllable mock for app.Cmd.
type MockCmd struct {
	StartErr      error
	WaitErr       error
	RunErr        error
	Stdout        []byte
	Stderr        []byte
	StdinPipeErr  error
	StdoutPipeErr error
	StderrPipeErr error
	SetEnvCalled  []string
	SetStdoutW    io.Writer
	SetStderrW    io.Writer
	SetStdinR     io.Reader

	// Track method calls for assertions if needed
	Started   bool
	Waited    bool
	Ran       bool
	StdoutSet bool
	StderrSet bool
	StdinSet  bool

	// For legacy fixture support
	T       *testing.T
	Fixture string
}

// Simulate the Start method.
func (c *MockCmd) Start() error {
	c.Started = true
	return c.StartErr
}

func (c *MockCmd) Wait() error {
	c.Waited = true
	return c.WaitErr
}

func (c *MockCmd) Run() error {
	c.Ran = true
	return c.RunErr
}

func (c *MockCmd) StdoutPipe() (io.ReadCloser, error) {
	if c.StdoutPipeErr != nil {
		return nil, c.StdoutPipeErr
	}
	if c.Fixture != "" && c.T != nil {
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
	return io.NopCloser(bytes.NewReader(c.Stdout)), nil
}

func (c *MockCmd) StderrPipe() (io.ReadCloser, error) {
	if c.StderrPipeErr != nil {
		return nil, c.StderrPipeErr
	}
	return io.NopCloser(bytes.NewReader(c.Stderr)), nil
}

func (c *MockCmd) StdinPipe() (io.WriteCloser, error) {
	if c.StdinPipeErr != nil {
		return nil, c.StdinPipeErr
	}
	return &mockWriteCloser{}, nil
}

func (c *MockCmd) SetEnv(env []string) {
	c.SetEnvCalled = env
}
func (c *MockCmd) SetStdout(w io.Writer) {
	c.StdoutSet = true
	c.SetStdoutW = w
}
func (c *MockCmd) SetStderr(w io.Writer) {
	c.StderrSet = true
	c.SetStderrW = w
}
func (c *MockCmd) SetStdin(r io.Reader) {
	c.StdinSet = true
	c.SetStdinR = r
}

// MockWriteCloser for StdinPipe
type mockWriteCloser struct {
	buf bytes.Buffer
	Err error
}

func (m *mockWriteCloser) Write(p []byte) (n int, err error) {
	if m.Err != nil {
		return 0, m.Err
	}
	return m.buf.Write(p)
}
func (m *mockWriteCloser) Close() error { return nil }

// MockCommandRunner returns the same mockCmd every time unless Fixtures map is provided.
type MockCommandRunner struct {
	Cmd      *MockCmd
	Fixtures map[string]string // command name → fixture filename
	T        *testing.T
}

// Command returns a mock Cmd. If Fixtures map is present it will try to
// return a MockCmd backed by the fixture name. If the fixture is not found
// the function will fall back to returning m.Cmd if set, or a default MockCmd,
// rather than fatalling the test. This makes the runner tolerant of incidental
// commands like "psql" that tests don't explicitly stub.
func (m *MockCommandRunner) Command(name string, args ...string) app.Cmd {
	// If Fixtures is set, try to use fixture for the command.
	if m.Fixtures != nil && m.T != nil {
		if fixture, ok := m.Fixtures[name]; ok {
			return &MockCmd{T: m.T, Fixture: fixture}
		}
		// fallback to provided Cmd if available
		if m.Cmd != nil {
			return m.Cmd
		}
		// otherwise return a harmless default MockCmd (no fatal)
		return &MockCmd{}
	}
	// No fixtures configured; return explicit Cmd if present
	if m.Cmd != nil {
		return m.Cmd
	}
	// Default to an empty MockCmd
	return &MockCmd{}
}

// Utility for error simulation in tests
func NewFailingMockCommandRunner(startErr, waitErr, stdinErr, stdoutErr, stderrErr error) *MockCommandRunner {
	return &MockCommandRunner{
		Cmd: &MockCmd{
			StartErr:      startErr,
			WaitErr:       waitErr,
			StdinPipeErr:  stdinErr,
			StdoutPipeErr: stdoutErr,
			StderrPipeErr: stderrErr,
		},
	}
}

// Example for test code:
//   runner := &testutils.MockCommandRunner{Cmd: &testutils.MockCmd{StartErr: errors.New("fail")}}
