package tests

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func newTestAppWithMockAWS() *app.App {
	return &app.App{
		Router:        gin.New(),
		DB:            TestApp.DB,
		Log:           TestApp.Log,
		Mongo:         TestApp.Mongo,
		AWS:           &testutils.MockAWSAdminError{},
		CommandRunner: TestApp.CommandRunner,
	}
}

func TestWibble_ListAWSUsers(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	//os.Setenv("ENVIRONMENT", "DEV")
	//defer os.Unsetenv("ENVIRONMENT")

	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)

	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)
	TestApp.Log.Info().Msgf("TOKEN FROM Wibble_ListAWSUsers IS [%s]", token)

	testApp := newTestAppWithMockAWS()

	// Register only the route and middleware you need for this test
	testApp.Router.GET("/admin/aws/users",
		testApp.AuthMiddleware(false),
		testApp.AccessControlMiddleware([]string{"super", "admin", "aws"}),
		func(c *gin.Context) {
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
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	//assert.Contains(t, resp, "error")
	assert.Contains(t, w.Body.String(), "oopsy")
	//assert.Equal(t, "mock AWS error", resp["error"])
}

func TestWibble_CreateUser(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)

	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser, "SUPERUSER env var must be set")
	require.NotEmpty(t, superPass, "SUPERPASS env var must be set")

	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)
	TestApp.Log.Info().Msgf("TOKEN FROM Wibble_CreateUser IS [%s]", token)

	// 1. Create a new user
	userUsername := "testuser1_" + testutils.RandString(8)
	userPassword := "testpass1"
	userReq := map[string]string{
		"username":         userUsername,
		"password":         base64.StdEncoding.EncodeToString([]byte(userPassword)),
		"confirm_password": base64.StdEncoding.EncodeToString([]byte(userPassword)),
	}
	body, _ := json.Marshal(userReq)
	req, err := http.NewRequest("POST", "/admin/user", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "user create should return 201")

	// 2. Validate user in DB
	testutils.SetUserValidated(t, TestApp, userUsername)

	// 3. Login as new user
	loginReq := map[string]string{
		"username": userUsername,
		"password": base64.StdEncoding.EncodeToString([]byte(userPassword)),
	}
	body, _ = json.Marshal(loginReq)
	req2, err := http.NewRequest("POST", "/admin/login", bytes.NewReader(body))
	require.NoError(t, err)
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w2, req2)
	require.Equal(t, http.StatusOK, w2.Code, "login as new user should return 200")
}

func TestWibble_FetchUser_HappyPath(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)

	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)

	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)

	userUsername := "fetchuser_" + testutils.RandString(8)
	userPassword := "fetchpass1"
	userReq := map[string]string{
		"username":         userUsername,
		"password":         base64.StdEncoding.EncodeToString([]byte(userPassword)),
		"confirm_password": base64.StdEncoding.EncodeToString([]byte(userPassword)),
	}
	body, _ := json.Marshal(userReq)
	req, err := http.NewRequest("POST", "/admin/user", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("y-access-token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	testutils.SetUserValidated(t, TestApp, userUsername)

	var user app.User
	err = TestApp.DB.Where("username = ?", userUsername).First(&user).Error
	require.NoError(t, err)
	require.NotEqual(t, uuid.Nil, user.AdminId)

	fetchReq, err := http.NewRequest("GET", "/admin/user/"+user.AdminId.String(), nil)
	require.NoError(t, err)
	fetchReq.Header.Set("y-access-token", token)
	w2 := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w2, fetchReq)
	require.Equal(t, http.StatusOK, w2.Code)
	require.Contains(t, w2.Body.String(), userUsername)
}
