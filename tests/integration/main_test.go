package integration

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"os"
	"testing"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/joho/godotenv"
)

var TestApp *app.App

func TestMain(m *testing.M) {
	// 0. Load .env file before anything else
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Could not load .env file:", err)
	}

	gin.SetMode(gin.ReleaseMode)
	TestApp = &app.App{}
	TestApp.Hooks = TestApp
	TestApp.Log = testutils.SetupLogger()
	TestApp.CommandRunner = &app.RealCommandRunner{}

	// 1. Migrate schema
	TestApp.InitialiseApp()

	// 2. Truncate and reseed postgres database and reset Mongo to defaults
	testutils.ResetPostgresDB(nil, TestApp)
	testutils.ResetMongoDB(nil, TestApp)

	code := m.Run()
	os.Exit(code)
}
