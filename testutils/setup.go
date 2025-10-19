package testutils

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/rs/zerolog"
)

func SetupLogger() *zerolog.Logger {
	var logWriter = os.Stdout
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
	zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	return &logger
}

func SetupTestApp(t *testing.T) *app.App {
	a := &app.App{}
	a.Log = SetupLogger()
	a.CommandRunner = &app.RealCommandRunner{}
	a.InitialiseApp()
	return a
}
