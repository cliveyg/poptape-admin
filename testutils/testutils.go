package testutils

import (
	"fmt"
	"github.com/joho/godotenv"
)

func LoadEnv() error {
	return godotenv.Load()
}

// Returns a test microservice name, e.g., "test_microservice1"
func TestMicroserviceName(n int) string {
	return fmt.Sprintf("test_microservice%d", n)
}
