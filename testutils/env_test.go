package testutils

import (
	"fmt"
	"os"
	"testing"
)

func TestDebugEnvFilePresence(t *testing.T) {
	wd, _ := os.Getwd()
	fmt.Println("Go test CWD:", wd)
	if _, err := os.Stat(".env"); err == nil {
		fmt.Println(".env file is present in Go test CWD")
	} else {
		fmt.Println(".env file is NOT present in Go test CWD")
	}
}
