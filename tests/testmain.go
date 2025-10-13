package tests

import (
	"fmt"
	"github.com/cliveyg/poptape-admin/app"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog"
	"log"
	"os"
	"strings"
	"testing"
	"time"
)

var TestApp *app.App

func setupLogger() *zerolog.Logger {
	var logWriter = os.Stdout
	if logFileName := os.Getenv("LOGFILE"); logFileName != "" {
		logFile, err := os.OpenFile(logFileName, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0644)
		if err == nil {
			logWriter = logFile
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
	_ = godotenv.Load()

	a := &app.App{}
	a.Log = setupLogger()
	a.CommandRunner = &app.RealCommandRunner{}

	a.InitialiseApp()
	TestApp = a

	code := m.Run()
	os.Exit(code)
}
