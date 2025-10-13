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

func newTestApp() *app.App {
	a := &app.App{}
	a.Log = setupLogger()
	a.CommandRunner = &app.RealCommandRunner{}
	a.InitialiseApp() // migrates DB, populates roles, superuser, microservices, etc.
	return a
}

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

	// truncate test-data tables (add any others you want to always clear)
	tables := []string{"saverecords", "creds", "role_cred_ms"}
	tables = append(tables, extraTables...)
	for _, table := range tables {
		if appInstance.DB.Migrator().HasTable(table) {
			stmt := fmt.Sprintf("TRUNCATE TABLE %s RESTART IDENTITY CASCADE;", table)
			err := appInstance.DB.Exec(stmt).Error
			if err != nil {
				failOrPanic(t, "Failed to truncate table %s: %v", table, err)
			}
		} else {
			fmt.Printf("Table %s does not exist, skipping truncate\n", table)
		}
	}

	// reset roles table to just the seeded roles
	if appInstance.DB.Migrator().HasTable("roles") {
		err := appInstance.DB.Exec("TRUNCATE TABLE roles RESTART IDENTITY CASCADE;").Error
		if err != nil {
			failOrPanic(t, "Failed to truncate roles: %v", err)
		}
		if err := appInstance.CreateRoles(); err != nil {
			failOrPanic(t, "Failed to reseed roles: %v", err)
		}
	} else {
		fmt.Println("Table roles does not exist, skipping truncate and reseed")
	}

	// reset microservices table to just the seeded microservices
	if appInstance.DB.Migrator().HasTable("microservices") {
		err := appInstance.DB.Exec("TRUNCATE TABLE microservices RESTART IDENTITY CASCADE;").Error
		if err != nil {
			failOrPanic(t, "Failed to truncate microservices: %v", err)
		}
		// need a superuser to associate as creator
		var superUserObj app.User
		err = appInstance.DB.First(&superUserObj, "username = ?", superUser).Error
		if err != nil {
			failOrPanic(t, "Failed to find superuser for microservices seeding: %v", err)
		}
		if err := appInstance.CreateMicroservices(superUserObj.AdminId); err != nil {
			failOrPanic(t, "Failed to reseed microservices: %v", err)
		}
	} else {
		fmt.Println("Table microservices does not exist, skipping truncate and reseed")
	}

	// reset users: delete all except superuser
	if appInstance.DB.Migrator().HasTable("users") {
		err := appInstance.DB.Exec("DELETE FROM users WHERE username <> ?", superUser).Error
		if err != nil {
			failOrPanic(t, "Failed to clear test users: %v", err)
		}
	} else {
		fmt.Println("Table users does not exist, skipping delete")
	}
}

// failOrPanic: fails the test if t != nil, otherwise panics (for use in global setup)
func failOrPanic(t *testing.T, format string, args ...interface{}) {
	if t != nil {
		t.Fatalf(format, args...)
	} else {
		panic(fmt.Sprintf(format, args...))
	}
}
