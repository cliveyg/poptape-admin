package tests

import (
	"os"
	"testing"

	"github.com/cliveyg/poptape-admin/app"
)

var TestApp *app.App

func TestMain(m *testing.M) {
	TestApp = &app.App{}
	TestApp.Log = setupLogger()
	TestApp.CommandRunner = &app.RealCommandRunner{}

	// 1. Migrate schema (creates tables)
	TestApp.InitialiseApp()

	// 2. Truncate and reseed database
	resetDB(nil, TestApp)

	code := m.Run()
	os.Exit(code)
}
