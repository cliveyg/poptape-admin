package testutils

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
	"time"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

func ResetPostgresDB(t *testing.T, a *app.App) {

	tables := []string{
		"user_role",
		"role_cred_ms",
		"users",
		"roles",
		"creds",
		"microservices",
		"save_records",
	}

	a.Log.Info().Msg("-=-=-=-=-=-=-=-=-=-=-=-=-= resetDB =-=-=-=-=-=-=-=-=-=-=-=-=-=-")

	for _, table := range tables {
		if a.DB.Migrator().HasTable(table) {
			stmt := fmt.Sprintf("TRUNCATE TABLE %s RESTART IDENTITY CASCADE;", table)
			if err := a.DB.Exec(stmt).Error; err != nil {
				if t != nil {
					t.Fatalf("Failed to truncate table %s: %v", table, err)
				} else {
					panic(fmt.Sprintf("Failed to truncate table %s: %v", table, err))
				}
			}
		}
	}
	a.Log.Debug().Msg("All tables cleared")

	if err := a.CreateRoles(); err != nil {
		if t != nil {
			t.Fatalf("Failed to reseed roles: %v", err)
		} else {
			panic(fmt.Sprintf("Failed to reseed roles: %v", err))
		}
	}
	adminId, err := a.CreateSuperUser()
	if err != nil {
		if t != nil {
			t.Fatalf("Failed to reseed superuser: %v", err)
		} else {
			panic(fmt.Sprintf("Failed to reseed superuser: %v", err))
		}
	}
	if err = a.CreateMicroservices(*adminId); err != nil {
		if t != nil {
			t.Fatalf("Failed to reseed microservices: %v", err)
		} else {
			panic(fmt.Sprintf("Failed to reseed microservices: %v", err))
		}
	}

	a.Log.Debug().Msg("Everything reseeded")
}

func GetAnyAdminId(t *testing.T, db *gorm.DB) uuid.UUID {
	var user app.User
	res := db.First(&user)
	if res.Error != nil {
		t.Fatalf("Could not retrieve user for admin id: %v", res.Error)
	}
	return user.AdminId
}

func CreateTestMicroservice(t *testing.T, db *gorm.DB, msName string) {
	createdBy := GetAnyAdminId(t, db)
	ms := app.Microservice{
		MSName:    msName,
		CreatedBy: createdBy,
	}
	res := db.Create(&ms)
	if res.Error != nil {
		t.Fatalf("Failed to create test microservice: %v", res.Error)
	}
}

func DropTestMicroservicesByPrefix(t *testing.T, db *gorm.DB, msPrefix string) {
	res := db.Where("ms_name LIKE ?", msPrefix+"%").Delete(&app.Microservice{})
	if res.Error != nil {
		t.Errorf("Failed to clean up test microservices: %v", res.Error)
	}
}

// InsertRoleCredMS inserts a unique RoleCredMS record for test setup.
func InsertRoleCredMS(t *testing.T, db *gorm.DB, microserviceId, credId uuid.UUID, roleName string, createdBy uuid.UUID) {
	// Guarantee uniqueness for the role_cred_ms composite key (microserviceId, credId, roleName)
	rcm := app.RoleCredMS{
		MicroserviceId: microserviceId,
		CredId:         credId,
		RoleName:       roleName,
		CreatedBy:      createdBy,
		Created:        time.Now(),
	}
	// Check for existing record before insert to avoid duplicates
	var existing app.RoleCredMS
	err := db.Where("microservice_id = ? AND cred_id = ? AND role_name = ?", microserviceId, credId, roleName).First(&existing).Error
	if err == nil {
		// Already exists, skip insert
		return
	}
	require.True(t, err == gorm.ErrRecordNotFound)
	require.NoError(t, db.Create(&rcm).Error)
}

// InsertSaveRecord inserts a unique SaveRecord into the DB for direct test setup.
func InsertSaveRecord(t *testing.T, db *gorm.DB, rec app.SaveRecord) {
	// Guarantee uniqueness for SaveRecord (assume SaveId is unique)
	if rec.SaveId == uuid.Nil {
		rec.SaveId = uuid.New()
	}
	// Check for existing record before insert to avoid duplicates
	var existing app.SaveRecord
	err := db.Where("save_id = ?", rec.SaveId).First(&existing).Error
	if err == nil {
		// Already exists, skip insert
		return
	}
	require.True(t, err == gorm.ErrRecordNotFound)
	require.NoError(t, db.Create(&rec).Error)
}
