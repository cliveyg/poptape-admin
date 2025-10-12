package main

import (
	"bytes"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"testing"
)

// DummyCommandRunner implements CommandRunner for test purposes.
type DummyCommandRunner struct{}

func (d *DummyCommandRunner) Command(name string, args ...string) Cmd { return nil }

func TestAppSmoke(t *testing.T) {
	var buf bytes.Buffer
	logger := zerolog.New(&buf)
	app := &App{
		Log:           &logger,
		CommandRunner: &DummyCommandRunner{},
	}
	app.InitialiseApp()
	assert.NotNil(t, app.Router)
}
