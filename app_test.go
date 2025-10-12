package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

// DummyCommandRunner implements CommandRunner for pure unit tests.
type DummyCommandRunner struct{}

func (d *DummyCommandRunner) Command(name string, args ...string) Cmd { return nil }

func TestAppStructInitialization(t *testing.T) {
	app := &App{
		Router:        gin.Default(),
		CommandRunner: &DummyCommandRunner{},
	}
	assert.NotNil(t, app.Router)
	assert.NotNil(t, app.CommandRunner)
}

func TestInitialiseAppSetsRouter(t *testing.T) {
	var buf bytes.Buffer
	logger := zerolog.New(&buf)
	app := &App{
		Log:           &logger,
		CommandRunner: &DummyCommandRunner{},
	}
	app.InitialiseApp()
	assert.NotNil(t, app.Router)
}

func TestRunStartsGinServer(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)
	var buf bytes.Buffer
	logger := zerolog.New(&buf)
	app := &App{
		Log:           &logger,
		CommandRunner: &DummyCommandRunner{},
	}
	app.Router = gin.New()
	app.Router.GET("/health", func(c *gin.Context) { c.String(200, "ok") })

	// Use httptest server instead of calling Run (which is blocking)
	ts := httptest.NewServer(app.Router)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	assert.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "ok", string(body))
}
