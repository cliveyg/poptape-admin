package testutils

import (
	"github.com/cliveyg/poptape-admin/app"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// SetupTestAppWithSQLite returns an App and a gorm.DB using in-memory SQLite with all necessary migrations.
func SetupTestAppWithSQLite() (*app.App, *gorm.DB) {
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
		//Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		panic(err)
	}
	// Add any additional models here as your handlers require
	_ = db.AutoMigrate(&app.Role{}, &app.Cred{}, &app.Microservice{}, &app.SaveRecord{}, &app.RoleCredMS{}, &app.User{})
	gormDB := app.NewGormDB(db)
	//logger := zerolog.New(os.Stdout)
	logger := zerolog.New(nil)
	a := &app.App{
		DB:  gormDB,
		Log: &logger,
	}
	return a, db
}
