package testutils

import (
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/cliveyg/poptape-admin/app"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// SetupTestAppWithSQLMock returns an App, *gorm.DB, and sqlmock.Sqlmock for unit tests.
// The sqlmock database is automatically closed after the test via t.Cleanup.
func SetupTestAppWithSQLMock(t *testing.T) (*app.App, *gorm.DB, sqlmock.Sqlmock) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	sqlDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	gormDb, err := gorm.Open(postgres.New(postgres.Config{
		Conn: sqlDB,
	}), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("failed to open gorm DB: %v", err)
	}

	log := SetupLogger() // from your testutils/setup.go
	a := &app.App{
		DB:  app.NewGormDB(gormDb),
		Log: log,
	}

	return a, gormDb, mock
}

// ExpectMicroserviceSelect sets up an expectation for the GORM FirstOrCreate microservice SELECT.
func ExpectMicroserviceSelect(mock sqlmock.Sqlmock) {
	mock.ExpectQuery(`SELECT \* FROM "microservices" WHERE "microservices"."ms_name" = .+ AND "microservices"."created_by" = .+ ORDER BY "microservices"."microservice_id" LIMIT .+`).
		WillReturnRows(sqlmock.NewRows([]string{"microservice_id"})) // Simulate not found
}

// MicroserviceRows returns sqlmock.Rows for a slice of app.Microservice
func MicroserviceRows(mss []app.Microservice) *sqlmock.Rows {
	rows := sqlmock.NewRows([]string{"microservice_id", "ms_name", "created_by", "created"})
	for _, ms := range mss {
		created := ms.Created
		if created.IsZero() {
			created = time.Now()
		}
		rows.AddRow(ms.MicroserviceId, ms.MSName, ms.CreatedBy, created)
	}
	return rows
}

// MockAssociation simulates gorm.Association for testing RemoveRoleFromUser.
type MockAssociation struct {
	clearErr error
}

func NewMockAssociation(clearErr error) *MockAssociation {
	return &MockAssociation{clearErr: clearErr}
}

func (m *MockAssociation) Clear() error {
	return m.clearErr
}

// ExpectUserCreate sets up sqlmock expectations for a successful user creation.
func ExpectUserCreate(mock sqlmock.Sqlmock) {
	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO "users"`).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
}

// ExpectUserCreateAndSave sets up sqlmock for successful user creation and Save (DEV mode).
func ExpectUserCreateAndSave(mock sqlmock.Sqlmock) {
	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO "users"`).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE "users"`).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
}

// ExpectUserCreateError sets up sqlmock for user creation error.
func ExpectUserCreateError(mock sqlmock.Sqlmock) {
	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO "users"`).WillReturnError(errors.New("insert failed"))
	mock.ExpectRollback()
}

// ExpectUserCreateAndSaveError sets up sqlmock for Save error after user creation (DEV mode).
func ExpectUserCreateAndSaveError(mock sqlmock.Sqlmock) {
	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO "users"`).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE "users"`).WillReturnError(errors.New("save failed"))
	mock.ExpectRollback()
}

// SeedAdminRole sets up the mock so the "admin" role exists
func SeedAdminRole(mock sqlmock.Sqlmock) {
	mock.ExpectQuery(`SELECT \* FROM "roles" WHERE "roles"."name" = \$1`).
		WithArgs("admin").
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow(1, "admin"))
}

// Simulate the admin role always existing
func ExpectAdminRoleExists(mock sqlmock.Sqlmock) {
	mock.ExpectQuery(`SELECT \* FROM "roles" WHERE "roles"."name" = \$1`).
		WithArgs("admin").
		WillReturnRows(sqlmock.NewRows([]string{"name", "created"}).AddRow("admin", time.Now()))
}

// Simulate the user_role join table insert
func ExpectUserRoleJoin(mock sqlmock.Sqlmock) {
	mock.ExpectExec(`INSERT INTO "user_role"`).WillReturnResult(sqlmock.NewResult(1, 1))
}
