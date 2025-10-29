package testutils

import (
	"encoding/base64"
	"errors"
	"github.com/cliveyg/poptape-admin/app"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"io"
	"testing"
	"time"
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
	//loggr := zerolog.New(os.Stdout)
	loggr := zerolog.New(io.Discard)
	a := &app.App{
		DB:  gormDB,
		Log: &loggr,
	}
	return a, db
}

// CreateTestRole inserts a role with the given name into the DB.
func CreateTestRole(t *testing.T, db *gorm.DB, roleName string) {
	role := &app.Role{Name: roleName, Created: time.Now()}
	require.NoError(t, db.Create(role).Error)
}

// CreateTestUser inserts a minimally valid user into the DB and returns it.
func CreateTestUser(t *testing.T, db *gorm.DB, username string) app.User {
	user := app.User{
		AdminId:   uuid.New(),
		Username:  username,
		Password:  []byte("irrelevant"),
		Active:    true,
		Validated: true,
		Created:   time.Now(),
		Updated:   time.Now(),
	}
	require.NoError(t, db.Create(&user).Error)
	return user
}

func CreateTestUserWithRole(t *testing.T, db *gorm.DB, username, roleName string) app.User {
	user := app.User{
		AdminId:   uuid.New(),
		Username:  username,
		Password:  []byte("irrelevant"),
		Active:    true,
		Validated: true,
		Created:   time.Now(),
		Updated:   time.Now(),
	}
	// Find the role
	var role app.Role
	require.NoError(t, db.First(&role, "name = ?", roleName).Error)
	// Assign role
	user.Roles = []app.Role{role}
	require.NoError(t, db.Create(&user).Error)
	return user
}

func ForceCreateError(db *gorm.DB) {
	db.Callback().Create().Before("gorm:create").Register("force_create_error", func(tx *gorm.DB) {
		tx.Error = errors.New("forced error for test")
	})
}

func CreateTestCred(db *gorm.DB) (*app.Cred, error) {
	rawPassword := "testpass"
	b64Password := base64.StdEncoding.EncodeToString([]byte(rawPassword))

	cred := app.Cred{
		DBName:     "test_db",
		Host:       "localhost",
		Type:       "postgres",
		URL:        "postgres://localhost:5432/test_db",
		DBPort:     "5432",
		DBUsername: "test_user",
		DBPassword: b64Password,
		LastUsed:   time.Now(),
		LastUsedBy: "testuser",
		CreatedBy:  uuid.New(),
	}

	if err := app.EncryptCredPass(&cred); err != nil {
		return nil, err
	}

	if err := db.Create(&cred).Error; err != nil {
		return nil, err
	}
	return &cred, nil
}
