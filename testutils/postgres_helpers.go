package testutils

import (
	"fmt"
	"os"
	"testing"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestPostgresDB(t *testing.T) *gorm.DB {
	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		os.Getenv("POSTGRES_HOST"),
		os.Getenv("POSTGRES_PORT"),
		os.Getenv("POSTGRES_USERNAME"),
		os.Getenv("POSTGRES_PASSWORD"),
		os.Getenv("POSTGRES_DBNAME"),
	)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to connect to postgres: %v", err)
	}
	return db
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
