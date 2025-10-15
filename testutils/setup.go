package testutils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/stretchr/testify/require"
)

func LoginAndGetToken(t *testing.T, testApp *app.App, username, password string) string {
	loginReq := map[string]string{
		"username": username,
		"password": password,
	}
	body, _ := json.Marshal(loginReq)
	req, err := http.NewRequest("POST", "/admin/login", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	testApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, "login should return 200")

	var out struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&out))
	require.NotEmpty(t, out.Token)
	return out.Token
}

func SetUserValidated(t *testing.T, testApp *app.App, username string) {
	result := testApp.DB.Model(&app.User{}).Where("username = ?", username).Update("validated", true)
	require.NoError(t, result.Error)
}

func RandString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[int64(len(letters))*int64(os.Getpid()+i)%int64(len(letters))]
	}
	return string(b)
}

func ResetDB(t *testing.T, a *app.App) {
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
