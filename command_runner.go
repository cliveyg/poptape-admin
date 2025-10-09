package main

import (
	"io"
	"os/exec"
)

// CommandRunner abstracts how commands are created and run.
type CommandRunner interface {
	Command(name string, args ...string) Cmd
}

// Cmd abstracts exec.Cmd for testability and mocking.
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

// RealCommandRunner is the production implementation using os/exec.
type RealCommandRunner struct{}

func (r *RealCommandRunner) Command(name string, args ...string) Cmd {
	return &RealCmd{cmd: exec.Command(name, args...)}
}

type RealCmd struct {
	cmd *exec.Cmd
}

func (c *RealCmd) Start() error                       { return c.cmd.Start() }
func (c *RealCmd) Run() error                         { return c.cmd.Run() }
func (c *RealCmd) Wait() error                        { return c.cmd.Wait() }
func (c *RealCmd) StdoutPipe() (io.ReadCloser, error) { return c.cmd.StdoutPipe() }
func (c *RealCmd) StderrPipe() (io.ReadCloser, error) { return c.cmd.StderrPipe() }
func (c *RealCmd) StdinPipe() (io.WriteCloser, error) { return c.cmd.StdinPipe() }
func (c *RealCmd) SetEnv(env []string)                { c.cmd.Env = env }
func (c *RealCmd) SetStdout(w io.Writer)              { c.cmd.Stdout = w }
func (c *RealCmd) SetStderr(w io.Writer)              { c.cmd.Stderr = w }
func (c *RealCmd) SetStdin(r io.Reader)               { c.cmd.Stdin = r }
