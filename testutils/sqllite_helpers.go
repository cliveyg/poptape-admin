package testutils

import (
	"github.com/cliveyg/poptape-admin/app"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	_ "modernc.org/sqlite"
	"net/http/httptest"
)

// SetupTestAppWithSQLite returns an App and a gorm.DB using in-memory SQLite with all necessary migrations.
func SetupTestAppWithSQLite() (*app.App, *gorm.DB) {
	// Use the modernc.org/sqlite driver by ensuring it is imported above.
	// GORM's sqlite driver will detect and use it if CGO is disabled and mattn/go-sqlite3 is not present.
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		panic(err)
	}
	// Add any additional models here as your handlers require
	_ = db.AutoMigrate(&app.Role{}, &app.Cred{}, &app.Microservice{}, &app.SaveRecord{}, &app.RoleCredMS{}, &app.User{})
	gormDB := app.NewGormDB(db)
	logger := zerolog.New(nil)
	a := &app.App{
		DB:  gormDB,
		Log: &logger,
	}
	return a, db
}

// CreateGinContextWithUser returns a Gin Context and ResponseRecorder with the given user set.
func CreateGinContextWithUser(user app.User) (*gin.Context, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("user", user)
	return c, w
}
