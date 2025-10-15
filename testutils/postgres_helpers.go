package testutils

import (
	"fmt"
	"testing"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

func ResetPostgresDB(t *testing.T, a *app.App) {
	tables := []string{
		"saverecords",
		"creds",
		"role_cred_ms",
		"users",
		"roles",
		"microservices",
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
