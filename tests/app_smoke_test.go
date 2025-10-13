package tests

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestApp_StartupSmokeTest(t *testing.T) {
	require.NotNil(t, TestApp)
	require.NotNil(t, TestApp.Router)
	require.NotNil(t, TestApp.DB)

	// admin/status route is live and returns expected fields/values
	req := httptest.NewRequest("GET", "/admin/status", nil)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	require.Contains(t, resp, "message")
	require.Equal(t, "System running...", resp["message"])

	require.Contains(t, resp, "version")
	expectedVersion := os.Getenv("VERSION")
	require.Equal(t, expectedVersion, resp["version"])
}
