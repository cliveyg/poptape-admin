package tests

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
)

func TestListAllSavesByMicroservice_NoRecords(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	msID := uuid.New()
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)
	url := fmt.Sprintf("/admin/microservice/%s/saves", msID.String())
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusNotFound, w.Code)
	require.Contains(t, w.Body.String(), "No saves found")
}

func TestListAllSavesByMicroservice_OneRecordForMS(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	msID := uuid.New()
	saveID := uuid.New()
	now := time.Now()
	testutils.InsertSaveRecord(t, TestApp.DB, app.SaveRecord{
		SaveId:         saveID,
		MicroserviceId: msID,
		CredId:         uuid.New(),
		DBName:         "testdb",
		Table:          "testtable",
		SavedBy:        "tester",
		Version:        1,
		Dataset:        1,
		Mode:           "full",
		Valid:          true,
		Type:           "postgres",
		Size:           42,
		Notes:          "ok",
		Created:        now,
		Updated:        now,
	})
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)
	url := fmt.Sprintf("/admin/microservice/%s/saves", msID.String())
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	saves, noOfSaves := testutils.ExtractSavesList(t, w.Body.Bytes())
	require.Equal(t, 1, noOfSaves)
	require.Equal(t, saveID, saves[0].SaveId)
	require.Equal(t, msID, saves[0].MicroserviceId)
}

func TestListAllSavesByMicroservice_OneForOtherMS_OneForTarget(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	msID := uuid.New()
	otherID := uuid.New()
	saveID := uuid.New()
	otherSaveID := uuid.New()
	now := time.Now()

	testutils.InsertSaveRecord(t, TestApp.DB, app.SaveRecord{
		SaveId:         otherSaveID,
		MicroserviceId: otherID,
		CredId:         uuid.New(),
		DBName:         "otherdb",
		Table:          "othertable",
		SavedBy:        "tester",
		Version:        1,
		Dataset:        1,
		Mode:           "full",
		Valid:          true,
		Type:           "postgres",
		Size:           21,
		Notes:          "other",
		Created:        now,
		Updated:        now,
	})
	testutils.InsertSaveRecord(t, TestApp.DB, app.SaveRecord{
		SaveId:         saveID,
		MicroserviceId: msID,
		CredId:         uuid.New(),
		DBName:         "testdb",
		Table:          "testtable",
		SavedBy:        "tester",
		Version:        2,
		Dataset:        2,
		Mode:           "full",
		Valid:          true,
		Type:           "postgres",
		Size:           42,
		Notes:          "target",
		Created:        now,
		Updated:        now,
	})
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)
	url := fmt.Sprintf("/admin/microservice/%s/saves", msID.String())
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	saves, noOfSaves := testutils.ExtractSavesList(t, w.Body.Bytes())
	require.Equal(t, 1, noOfSaves)
	require.Equal(t, saveID, saves[0].SaveId)
	require.Equal(t, msID, saves[0].MicroserviceId)
}

func TestListAllSavesByMicroservice_InvalidMicroserviceId(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)
	url := "/admin/microservice/not-a-uuid/saves"
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "Microservice id is invalid")
}

func TestListAllSavesByMicroservice_InvalidValidQuery(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	msID := uuid.New()
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)
	url := fmt.Sprintf("/admin/microservice/%s/saves?valid=notabool", msID.String())
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "Value of 'valid' querystring is invalid")
}

func TestListAllSavesByMicroservice_FilterValidTrue(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	msID := uuid.New()
	now := time.Now()

	testutils.InsertSaveRecord(t, TestApp.DB, app.SaveRecord{
		SaveId:         uuid.New(),
		MicroserviceId: msID,
		CredId:         uuid.New(),
		DBName:         "validdb1",
		Table:          "table1",
		SavedBy:        "tester",
		Version:        1,
		Dataset:        1,
		Mode:           "full",
		Valid:          true,
		Type:           "postgres",
		Size:           42,
		Notes:          "valid save 1",
		Created:        now,
		Updated:        now,
	})
	testutils.InsertSaveRecord(t, TestApp.DB, app.SaveRecord{
		SaveId:         uuid.New(),
		MicroserviceId: msID,
		CredId:         uuid.New(),
		DBName:         "validdb2",
		Table:          "table2",
		SavedBy:        "tester",
		Version:        2,
		Dataset:        2,
		Mode:           "full",
		Valid:          true,
		Type:           "postgres",
		Size:           43,
		Notes:          "valid save 2",
		Created:        now,
		Updated:        now,
	})
	testutils.InsertSaveRecord(t, TestApp.DB, app.SaveRecord{
		SaveId:         uuid.New(),
		MicroserviceId: msID,
		CredId:         uuid.New(),
		DBName:         "invaliddb",
		Table:          "table3",
		SavedBy:        "tester",
		Version:        3,
		Dataset:        3,
		Mode:           "full",
		Valid:          false,
		Type:           "postgres",
		Size:           44,
		Notes:          "invalid save",
		Created:        now,
		Updated:        now,
	})
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)
	url := fmt.Sprintf("/admin/microservice/%s/saves?valid=true", msID.String())
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	saves, noOfSaves := testutils.ExtractSavesList(t, w.Body.Bytes())
	require.Equal(t, 2, noOfSaves)
	for _, save := range saves {
		require.True(t, save.Valid)
		require.Equal(t, msID, save.MicroserviceId)
	}
}

func TestListAllSavesByMicroservice_FilterValidFalse(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	msID := uuid.New()
	now := time.Now()

	testutils.InsertSaveRecord(t, TestApp.DB, app.SaveRecord{
		SaveId:         uuid.New(),
		MicroserviceId: msID,
		CredId:         uuid.New(),
		DBName:         "validdb1",
		Table:          "table1",
		SavedBy:        "tester",
		Version:        1,
		Dataset:        1,
		Mode:           "full",
		Valid:          true,
		Type:           "postgres",
		Size:           42,
		Notes:          "valid save 1",
		Created:        now,
		Updated:        now,
	})
	testutils.InsertSaveRecord(t, TestApp.DB, app.SaveRecord{
		SaveId:         uuid.New(),
		MicroserviceId: msID,
		CredId:         uuid.New(),
		DBName:         "invaliddb1",
		Table:          "table2",
		SavedBy:        "tester",
		Version:        2,
		Dataset:        2,
		Mode:           "full",
		Valid:          false,
		Type:           "postgres",
		Size:           43,
		Notes:          "invalid save 1",
		Created:        now,
		Updated:        now,
	})
	testutils.InsertSaveRecord(t, TestApp.DB, app.SaveRecord{
		SaveId:         uuid.New(),
		MicroserviceId: msID,
		CredId:         uuid.New(),
		DBName:         "validdb2",
		Table:          "table3",
		SavedBy:        "tester",
		Version:        3,
		Dataset:        3,
		Mode:           "full",
		Valid:          true,
		Type:           "postgres",
		Size:           44,
		Notes:          "valid save 2",
		Created:        now,
		Updated:        now,
	})
	testutils.InsertSaveRecord(t, TestApp.DB, app.SaveRecord{
		SaveId:         uuid.New(),
		MicroserviceId: msID,
		CredId:         uuid.New(),
		DBName:         "invaliddb2",
		Table:          "table4",
		SavedBy:        "tester",
		Version:        4,
		Dataset:        4,
		Mode:           "full",
		Valid:          false,
		Type:           "postgres",
		Size:           45,
		Notes:          "invalid save 2",
		Created:        now,
		Updated:        now,
	})
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)
	url := fmt.Sprintf("/admin/microservice/%s/saves?valid=false", msID.String())
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	saves, noOfSaves := testutils.ExtractSavesList(t, w.Body.Bytes())
	require.Equal(t, 2, noOfSaves)
	for _, save := range saves {
		require.False(t, save.Valid)
		require.Equal(t, msID, save.MicroserviceId)
	}
}

func TestListAllSavesByMicroservice_FilterValidTrue_NoRecords(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	msID := uuid.New()
	now := time.Now()
	testutils.InsertSaveRecord(t, TestApp.DB, app.SaveRecord{
		SaveId:         uuid.New(),
		MicroserviceId: msID,
		CredId:         uuid.New(),
		DBName:         "invaliddb1",
		Table:          "table1",
		SavedBy:        "tester",
		Version:        1,
		Dataset:        1,
		Mode:           "full",
		Valid:          false,
		Type:           "postgres",
		Size:           42,
		Notes:          "invalid save 1",
		Created:        now,
		Updated:        now,
	})
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)
	url := fmt.Sprintf("/admin/microservice/%s/saves?valid=true", msID.String())
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusNotFound, w.Code)
	require.Contains(t, w.Body.String(), "No saves found")
}

func TestListAllSavesByMicroservice_FilterValidFalse_NoRecords(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	msID := uuid.New()
	now := time.Now()
	testutils.InsertSaveRecord(t, TestApp.DB, app.SaveRecord{
		SaveId:         uuid.New(),
		MicroserviceId: msID,
		CredId:         uuid.New(),
		DBName:         "validdb1",
		Table:          "table1",
		SavedBy:        "tester",
		Version:        1,
		Dataset:        1,
		Mode:           "full",
		Valid:          true,
		Type:           "postgres",
		Size:           42,
		Notes:          "valid save 1",
		Created:        now,
		Updated:        now,
	})
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)
	url := fmt.Sprintf("/admin/microservice/%s/saves?valid=false", msID.String())
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusNotFound, w.Code)
	require.Contains(t, w.Body.String(), "No saves found")
}
