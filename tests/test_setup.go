package tests

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/rs/zerolog"
)

var TestApp *app.App

func setupLogger() *zerolog.Logger {
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
	return &logger
}

// newTestApp creates and initializes a new App and database with all seed data.
func newTestApp() *app.App {
	a := &app.App{}
	a.Log = setupLogger()
	a.CommandRunner = &app.RealCommandRunner{}
	a.InitialiseApp() // migrates DB, populates roles, superuser, microservices, etc.
	return a
}

// resetTestApp resets the global TestApp and the DB to the seeded state plus resets test tables.
func resetTestApp(t *testing.T) {
	TestApp = newTestApp()
	resetTestDB(t, TestApp)
}

// resetTestDB:
// - Truncates test-only tables (saverecords, creds, role_cred_ms, add more as needed)
// - Resets roles and microservices to their seed values (truncates + reseeds)
// - Deletes all users except the superuser (seeded user)
// You can optionally provide extra tables to reset as needed.
func resetTestDB(t *testing.T, appInstance *app.App, extraTables ...string) {
	superUser := os.Getenv("SUPERUSER")

	// 1. Truncate test-data tables (add any others you want to always clear)
	tables := []string{"saverecords", "creds", "role_cred_ms"}
	tables = append(tables, extraTables...)
	for _, table := range tables {
		stmt := fmt.Sprintf("TRUNCATE TABLE %s RESTART IDENTITY CASCADE;", table)
		err := appInstance.DB.Exec(stmt).Error
		if err != nil {
			failOrPanic(t, fmt.Sprintf("Failed to truncate table %s: %v", table, err))
		}
	}

	// 2. Reset roles table to just the seeded roles
	err := appInstance.DB.Exec("TRUNCATE TABLE roles RESTART IDENTITY CASCADE;").Error
	if err != nil {
		failOrPanic(t, fmt.Sprintf("Failed to truncate roles: %v", err))
	}
	if err = appInstance.CreateRoles(); err != nil {
		failOrPanic(t, fmt.Sprintf("Failed to reseed roles: %v", err))
	}

	// 3. Reset microservices table to just the seeded microservices
	err = appInstance.DB.Exec("TRUNCATE TABLE microservices RESTART IDENTITY CASCADE;").Error
	if err != nil {
		failOrPanic(t, fmt.Sprintf("Failed to truncate microservices: %v", err))
	}
	// Need a superuser to associate as creator
	var superUserObj app.User
	err = appInstance.DB.First(&superUserObj, "username = ?", superUser).Error
	if err != nil {
		failOrPanic(t, fmt.Sprintf("Failed to find superuser for microservices seeding: %v", err))
	}
	if err = appInstance.CreateMicroservices(superUserObj.AdminId); err != nil {
		failOrPanic(t, fmt.Sprintf("Failed to reseed microservices: %v", err))
	}

	// 4. Reset users: delete all except superuser
	err = appInstance.DB.Exec("DELETE FROM users WHERE username <> ?", superUser).Error
	if err != nil {
		failOrPanic(t, fmt.Sprintf("Failed to clear test users: %v", err))
	}
}

// failOrPanic: fails the test if t != nil, otherwise panics (for use in global setup)
func failOrPanic(t *testing.T, msg string) {
	if t != nil {
		t.Fatalf(msg)
	} else {
		panic(msg)
	}
}
