package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/stretchr/testify/assert"
)

func TestListAllPoptapeStandardUsers_HappyPath(t *testing.T) {
	ctx := context.Background()
	iamClient := testutils.GetAWSIAMClient(ctx)

	// Ensure clean slate
	testutils.ClearAllIAMUsers(ctx, iamClient)

	// Seed users: 2 standard, 2 others (different path and no path)
	usersToSeed := map[string]string{
		"stduser1": "/poptape-standard-users/",
		"stduser2": "/poptape-standard-users/",
		"other1":   "/other-type/",
		"other2":   "/",
	}
	cleanup := testutils.SeedIAMUsersWithPaths(ctx, iamClient, usersToSeed)
	defer cleanup()

	// Call the route
	req, _ := http.NewRequest(http.MethodGet, "/admin/aws/users", nil)
	// If auth is required, add headers/cookies here

	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Parse response and check only standard users are counted
	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)

	assert.Equal(t, float64(2), resp["no_of_standard_users"])

	// Optional: check returned user_details only have correct Path
	if details, ok := resp["user_details"].([]interface{}); ok {
		for _, u := range details {
			m, ok := u.(map[string]interface{})
			if ok {
				assert.Equal(t, "/poptape-standard-users/", m["Path"])
			}
		}
	}
}

func TestListAllPoptapeStandardUsers_ZeroStandardUsers(t *testing.T) {
	ctx := context.Background()
	iamClient := testutils.GetAWSIAMClient(ctx)

	// Ensure clean slate
	testutils.ClearAllIAMUsers(ctx, iamClient)

	// Seed only non-standard users
	usersToSeed := map[string]string{
		"other1": "/other-type/",
		"other2": "/",
	}
	cleanup := testutils.SeedIAMUsersWithPaths(ctx, iamClient, usersToSeed)
	defer cleanup()

	req, _ := http.NewRequest(http.MethodGet, "/admin/aws/users", nil)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, float64(0), resp["no_of_standard_users"])
	if details, ok := resp["user_details"].([]interface{}); ok {
		assert.Len(t, details, 0)
	}
}
