package tests

import (
	"fmt"
	"os"
	"testing"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/joho/godotenv"
)

var TestApp *app.App

func TestMain(m *testing.M) {
	// 0. Load .env file before anything else
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Could not load .env file:", err)
	}

	// Print env to confirm
	fmt.Println("POSTGRES_USERNAME:", os.Getenv("POSTGRES_USERNAME"))
	fmt.Println("POSTGRES_DBNAME:", os.Getenv("POSTGRES_DBNAME"))
	fmt.Println("POSTGRES_HOST:", os.Getenv("POSTGRES_HOST"))

	TestApp = &app.App{}
	TestApp.Log = setupLogger()
	TestApp.CommandRunner = &app.RealCommandRunner{}

	// 1. Migrate schema
	TestApp.InitialiseApp()

	// 2. Truncate and reseed database
	resetDB(nil, TestApp)

	code := m.Run()
	os.Exit(code)
}
