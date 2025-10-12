package testutils

import (
	"fmt"
	"os"
	"testing"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Postgres helpers

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

func CreateTestMicroservice(t *testing.T, db *gorm.DB, msName string) {
	type Microservice struct {
		MicroserviceId string `gorm:"primaryKey;type:uuid"`
		MSName         string
		Created        time.Time
	}
	ms := Microservice{
		MSName:  msName,
		Created: time.Now(),
	}
	res := db.Create(&ms)
	if res.Error != nil {
		t.Fatalf("Failed to create test microservice: %v", res.Error)
	}
}

func DropTestMicroservicesByPrefix(t *testing.T, db *gorm.DB, msPrefix string) {
	type Microservice struct {
		MicroserviceId string `gorm:"primaryKey;type:uuid"`
		MSName         string
	}
	res := db.Where("ms_name LIKE ?", msPrefix+"%").Delete(&Microservice{})
	if res.Error != nil {
		t.Errorf("Failed to clean up test microservices: %v", res.Error)
	}
}
