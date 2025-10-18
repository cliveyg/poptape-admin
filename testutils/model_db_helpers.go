package testutils

import (
	"encoding/base64"
	"errors"
	"github.com/cliveyg/poptape-admin/app"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"testing"
	"time"
)

// DefaultCreateCredsPayload returns a flat map with all required fields for a CreateCreds request.
// Modify the returned map in your test as needed for specific scenarios.
func DefaultCreateCredsPayload() map[string]interface{} {
	return map[string]interface{}{
		"db_name":     "poptape_items",
		"type":        "mongo",
		"url":         "/items",
		"db_username": "poptape_items",
		"db_password": "cGFzc3dvcmQ=",
		"db_port":     "27017",
		"host":        "poptape-items-mongodb-1",
		"role_name":   "items",
		"ms_name":     "items",
	}
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
