package testutils

import (
	"fmt"
	"github.com/joho/godotenv"
	"testing"
)

// LoadEnv loads environment variables from .env for tests.
func LoadEnv(t *testing.T) {
	t.Helper()
	if err := godotenv.Load(); err != nil {
		t.Fatalf("Could not load .env file: %v", err)
	}
}

// Returns a test microservice name, e.g., "test_microservice1"
func TestMicroserviceName(n int) string {
	return fmt.Sprintf("test_microservice%d", n)
}
