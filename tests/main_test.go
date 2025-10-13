package tests

import (
	"github.com/joho/godotenv"
	"log"
	"os"
	"testing"
)

// This is optional if you want to load env vars for your tests.
func TestMain(m *testing.M) {
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}
	os.Exit(m.Run())
}
