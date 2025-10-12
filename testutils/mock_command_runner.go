package testutils

import (
	"bytes"
	"io"
)

// Cmd interface should match your command_runner.go interface.
type Cmd interface {
	Start() error
	Run() error
	Wait() error
	StdoutPipe() (io.ReadCloser, error)
	StderrPipe() (io.ReadCloser, error)
	StdinPipe() (io.WriteCloser, error)
	SetEnv(env []string)
	SetStdout(w io.Writer)
	SetStderr(w io.Writer)
	SetStdin(r io.Reader)
}

// MockCommandRunner implements CommandRunner for testing.
type MockCommandRunner struct {
	LastCmd  string
	LastArgs []string
	Stdout   string
	Stderr   string
	Err      error
}

func (m *MockCommandRunner) Command(name string, args ...string) Cmd {
	m.LastCmd = name
	m.LastArgs = args
	return &MockCmd{Stdout: m.Stdout, Stderr: m.Stderr, Err: m.Err}
}

type MockCmd struct {
	Stdout string
	Stderr string
	Err    error
}

func (m *MockCmd) Start() error { return m.Err }
func (m *MockCmd) Run() error   { return m.Err }
func (m *MockCmd) Wait() error  { return m.Err }
func (m *MockCmd) StdoutPipe() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewBufferString(m.Stdout)), nil
}
func (m *MockCmd) StderrPipe() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewBufferString(m.Stderr)), nil
}
func (m *MockCmd) StdinPipe() (io.WriteCloser, error) { return nil, nil }
func (m *MockCmd) SetEnv(env []string)                {}
func (m *MockCmd) SetStdout(w io.Writer)              {}
func (m *MockCmd) SetStderr(w io.Writer)              {}
func (m *MockCmd) SetStdin(r io.Reader)               {}
