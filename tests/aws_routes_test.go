package tests

import (
	"context"
	"encoding/json"
	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/utils"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/stretchr/testify/assert"
)

func TestListAllPoptapeStandardUsers_HappyPath(t *testing.T) {
	ctx := context.Background()
	iamClient := testutils.GetAWSIAMClient(ctx)

	// Ensure clean slate
	testutils.ClearAllIAMUsers(ctx, iamClient)

	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)

	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

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
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")
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

	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)

	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	// Seed only non-standard users
	usersToSeed := map[string]string{
		"other1": "/other-type/",
		"other2": "/",
	}
	cleanup := testutils.SeedIAMUsersWithPaths(ctx, iamClient, usersToSeed)
	defer cleanup()

	req, _ := http.NewRequest(http.MethodGet, "/admin/aws/users", nil)
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")
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

func TestListAllPoptapeStandardUsers_AWSError_DEV(t *testing.T) {
	os.Setenv("ENVIRONMENT", "DEV")
	defer os.Unsetenv("ENVIRONMENT")

	user := testutils.MakeTestUser()
	token, err := utils.GenerateToken(user.Username, user.AdminId)
	require.NoError(t, err)

	testApp := &app.App{
		AWS:    &testutils.MockAWSAdminError{},
		Log:    TestApp.Log,
		Router: gin.New(),
	}

	// Register route using exported middleware and inject user
	testApp.Router.GET("/admin/aws/users",
		testApp.AuthMiddleware(false),
		testApp.AccessControlMiddleware([]string{"super", "admin", "aws"}),
		func(c *gin.Context) {
			c.Set("user", user)
			testApp.ListAllPoptapeStandardUsers(c)
		},
	)

	req, _ := http.NewRequest(http.MethodGet, "/admin/aws/users", nil)
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	testApp.Router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	var resp map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Contains(t, resp, "error")
	assert.Equal(t, "mock AWS error", resp["error"])
}

func TestListAllPoptapeStandardUsers_AWSError_Prod(t *testing.T) {
	os.Unsetenv("ENVIRONMENT")

	user := testutils.MakeTestUser()
	token, err := utils.GenerateToken(user.Username, user.AdminId)
	require.NoError(t, err)

	testApp := &app.App{
		AWS:    &testutils.MockAWSAdminError{},
		Log:    TestApp.Log,
		Router: gin.New(),
	}

	testApp.Router.GET("/admin/aws/users",
		testApp.AuthMiddleware(false),
		testApp.AccessControlMiddleware([]string{"super", "admin", "aws"}),
		func(c *gin.Context) {
			c.Set("user", user)
			testApp.ListAllPoptapeStandardUsers(c)
		},
	)

	req, _ := http.NewRequest(http.MethodGet, "/admin/aws/users", nil)
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	testApp.Router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	var resp map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Contains(t, resp, "message")
	assert.Equal(t, "oopsy", resp["message"])
}
