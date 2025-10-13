package tests

import (
	"github.com/joho/godotenv"
	"log"
	"os"
	"testing"
)

// TestMain is recognized by the Go test runner and is run once per package.
func TestMain(m *testing.M) {
	// Load .env file for test credentials/config
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}
	// Set up the initial TestApp so it's available globally
	resetTestApp(nil)

	// Run all tests
	code := m.Run()
	os.Exit(code)
}
