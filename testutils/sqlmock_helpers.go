package testutils

import (
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

func (m *MockAssociation) Clear() error {
	return m.clearErr
}

// RoleRows returns sqlmock.Rows for a slice of app.Role
func RoleRows(roles []app.Role) *sqlmock.Rows {
	rows := sqlmock.NewRows([]string{"name", "created"})
	for _, r := range roles {
		created := r.Created
		if created.IsZero() {
			created = time.Now()
		}
		rows.AddRow(r.Name, created)
	}
	return rows
}

// SaveRecordRows returns sqlmock.Rows for a slice of app.SaveRecord
func SaveRecordRows(saves []app.SaveRecord) *sqlmock.Rows {
	rows := sqlmock.NewRows([]string{
		"save_id", "microservice_id", "cred_id", "db_name",
		"table", "saved_by", "version", "dataset", "mode",
		"valid", "type", "size", "notes", "created", "updated",
	})
	for _, s := range saves {
		created := s.Created
		if created.IsZero() {
			created = time.Now()
		}
		updated := s.Updated
		if updated.IsZero() {
			updated = created
		}
		rows.AddRow(
			s.SaveId, s.MicroserviceId, s.CredId, s.DBName,
			s.Table, s.SavedBy, s.Version, s.Dataset, s.Mode,
			s.Valid, s.Type, s.Size, s.Notes, created, updated,
		)
	}
	return rows
}
