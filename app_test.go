package main

import (
	"bytes"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

type DummyCommandRunner struct{}

func (d *DummyCommandRunner) Command(name string, args ...string) Cmd { return nil }

// AppWithStubAWS embeds App and stubs only InitialiseAWS
type AppWithStubAWS struct {
	App
}

func (a *AppWithStubAWS) InitialiseAWS() {}

func TestAppSmoke(t *testing.T) {
	var buf bytes.Buffer
	logger := zerolog.New(&buf)
	app := &AppWithStubAWS{
		App: App{
			Log:           &logger,
			CommandRunner: &DummyCommandRunner{},
		},
	}
	app.InitialiseApp()
	assert.NotNil(t, app.Router, "Router should not be nil after initialization")
	assert.NotNil(t, app.DB, "DB should not be nil after initialization")
	assert.NotNil(t, app.Mongo, "Mongo client should not be nil after initialization")
	// AWS may be nil because it's stubbed, that's OK for this test.
}
