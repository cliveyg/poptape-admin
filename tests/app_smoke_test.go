package tests

import (
	"context"
	"fmt"
	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog"
	"log"
	"os"
	"strings"
	"testing"
	"time"
)

func setupLogger() *zerolog.Logger {
	// Try to get log file from env, else default to stdout
	var logWriter = os.Stdout
	if logFileName := os.Getenv("LOGFILE"); logFileName != "" {
		logFile, err := os.OpenFile(logFileName, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0644)
		if err == nil {
			logWriter = logFile
			// If you want to close logFile at the end, you can add logic here
		} else {
			log.Printf("Could not open log file %s, using stdout: %v", logFileName, err)
		}
	}

	cw := zerolog.ConsoleWriter{Out: logWriter, NoColor: true, TimeFormat: time.RFC3339}
	cw.FormatLevel = func(i interface{}) string {
		return strings.ToUpper(fmt.Sprintf("[ %-6s]", i))
	}
	cw.TimeFormat = "[" + time.RFC3339 + "] - "
	cw.FormatCaller = func(i interface{}) string {
		str, _ := i.(string)
		return fmt.Sprintf("['%s']", str)
	}
	cw.PartsOrder = []string{
		zerolog.LevelFieldName,
		zerolog.TimestampFieldName,
		zerolog.MessageFieldName,
		zerolog.CallerFieldName,
	}

	logger := zerolog.New(cw).With().Timestamp().Caller().Logger()

	// Set log level
	switch os.Getenv("LOGLEVEL") {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	}

	return &logger
}

func TestMain(m *testing.M) {
	// Load .env like in production
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	a := &app.App{}
	a.Log = setupLogger()
	a.CommandRunner = &app.RealCommandRunner{}

	a.InitialiseApp()
	code := m.Run()
	os.Exit(code)
}

func TestHarnessSmokeTest(t *testing.T) {
	msName := testutils.TestMicroserviceName(1) // "test_microservice1"

	// MongoDB: Create dummy collection in test db, then drop it
	client := testutils.TestMongoClient(t)
	defer func() { _ = client.Disconnect(context.Background()) }()
	db := client.Database(msName)
	if err := db.CreateCollection(context.Background(), "fs.files"); err != nil {
		t.Fatalf("Failed to create dummy collection: %v", err)
	}
	testutils.DropTestMongoDatabases(t, client, "test_microservice")

	// Postgres: Create and drop test microservice
	dbpg := testutils.TestPostgresDB(t)
	testutils.CreateTestMicroservice(t, dbpg, msName)
	testutils.DropTestMicroservicesByPrefix(t, dbpg, "test_microservice")
}
