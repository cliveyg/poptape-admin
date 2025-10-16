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
	ms := app.Microservice{
		MicroserviceId: uuid.New(),
		MSName:         "testms",
		CreatedBy:      uuid.New(),
		Created:        time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&ms).Error)
	cred := app.Cred{
		CredId:  uuid.New(),
		DBName:  "testmsdb",
		Created: time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&cred).Error)
	testutils.InsertRoleCredMS(t, TestApp.DB, ms.MicroserviceId, cred.CredId, "admin", ms.CreatedBy)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)
	url := fmt.Sprintf("/admin/microservice/%s/saves", ms.MicroserviceId.String())
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusNotFound, w.Code)
	require.Contains(t, w.Body.String(), "No saves found")
}

func TestListAllSavesByMicroservice_OneRecordForMS(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	ms := app.Microservice{
		MicroserviceId: uuid.New(),
		MSName:         "testms2",
		CreatedBy:      uuid.New(),
		Created:        time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&ms).Error)
	cred := app.Cred{
		CredId:  uuid.New(),
		DBName:  "testms2db",
		Created: time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&cred).Error)
	testutils.InsertRoleCredMS(t, TestApp.DB, ms.MicroserviceId, cred.CredId, "admin", ms.CreatedBy)
	saveID := uuid.New()
	now := time.Now()
	testutils.InsertSaveRecord(t, TestApp.DB, app.SaveRecord{
		SaveId:         saveID,
		MicroserviceId: ms.MicroserviceId,
		CredId:         cred.CredId,
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
	url := fmt.Sprintf("/admin/microservice/%s/saves", ms.MicroserviceId.String())
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	saves, noOfSaves := testutils.ExtractSavesList(t, w.Body.Bytes())
	require.Equal(t, 1, noOfSaves)
	require.Equal(t, saveID, saves[0].SaveId)
	require.Equal(t, ms.MicroserviceId, saves[0].MicroserviceId)
}

func TestListAllSavesByMicroservice_OneForOtherMS_OneForTarget(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	ms := app.Microservice{
		MicroserviceId: uuid.New(),
		MSName:         "targetms",
		CreatedBy:      uuid.New(),
		Created:        time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&ms).Error)
	otherMS := app.Microservice{
		MicroserviceId: uuid.New(),
		MSName:         "otherms",
		CreatedBy:      uuid.New(),
		Created:        time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&otherMS).Error)
	cred := app.Cred{
		CredId:  uuid.New(),
		DBName:  "targetmsdb",
		Created: time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&cred).Error)
	otherCred := app.Cred{
		CredId:  uuid.New(),
		DBName:  "othermsdb",
		Created: time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&otherCred).Error)
	testutils.InsertRoleCredMS(t, TestApp.DB, ms.MicroserviceId, cred.CredId, "admin", ms.CreatedBy)
	testutils.InsertRoleCredMS(t, TestApp.DB, otherMS.MicroserviceId, otherCred.CredId, "admin", otherMS.CreatedBy)
	saveID := uuid.New()
	otherSaveID := uuid.New()
	now := time.Now()
	testutils.InsertSaveRecord(t, TestApp.DB, app.SaveRecord{
		SaveId:         otherSaveID,
		MicroserviceId: otherMS.MicroserviceId,
		CredId:         otherCred.CredId,
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
		MicroserviceId: ms.MicroserviceId,
		CredId:         cred.CredId,
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
	url := fmt.Sprintf("/admin/microservice/%s/saves", ms.MicroserviceId.String())
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	saves, noOfSaves := testutils.ExtractSavesList(t, w.Body.Bytes())
	require.Equal(t, 1, noOfSaves)
	require.Equal(t, saveID, saves[0].SaveId)
	require.Equal(t, ms.MicroserviceId, saves[0].MicroserviceId)
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
	require.Contains(t, w.Body.String(), "Bad request [ms]")
}

func TestListAllSavesByMicroservice_InvalidValidQuery(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	ms := app.Microservice{
		MicroserviceId: uuid.New(),
		MSName:         "testms4",
		CreatedBy:      uuid.New(),
		Created:        time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&ms).Error)
	cred := app.Cred{
		CredId:  uuid.New(),
		DBName:  "testms4db",
		Created: time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&cred).Error)
	testutils.InsertRoleCredMS(t, TestApp.DB, ms.MicroserviceId, cred.CredId, "admin", ms.CreatedBy)
	superUser := os.Getenv("SUPERUSER")
	superPass := os.Getenv("SUPERPASS")
	require.NotEmpty(t, superUser)
	require.NotEmpty(t, superPass)
	token := testutils.LoginAndGetToken(t, TestApp, superUser, superPass)
	url := fmt.Sprintf("/admin/microservice/%s/saves?valid=notabool", ms.MicroserviceId.String())
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "Value of 'valid' querystring is invalid")
}

func TestListAllSavesByMicroservice_FilterValidTrue(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	ms := app.Microservice{
		MicroserviceId: uuid.New(),
		MSName:         "testms5",
		CreatedBy:      uuid.New(),
		Created:        time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&ms).Error)
	cred := app.Cred{
		CredId:  uuid.New(),
		DBName:  "testms5db",
		Created: time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&cred).Error)
	testutils.InsertRoleCredMS(t, TestApp.DB, ms.MicroserviceId, cred.CredId, "admin", ms.CreatedBy)
	now := time.Now()
	testutils.InsertSaveRecord(t, TestApp.DB, app.SaveRecord{
		SaveId:         uuid.New(),
		MicroserviceId: ms.MicroserviceId,
		CredId:         cred.CredId,
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
		MicroserviceId: ms.MicroserviceId,
		CredId:         cred.CredId,
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
		MicroserviceId: ms.MicroserviceId,
		CredId:         cred.CredId,
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
	url := fmt.Sprintf("/admin/microservice/%s/saves?valid=true", ms.MicroserviceId.String())
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	saves, noOfSaves := testutils.ExtractSavesList(t, w.Body.Bytes())
	require.Equal(t, 2, noOfSaves)
	for _, save := range saves {
		require.True(t, save.Valid)
		require.Equal(t, ms.MicroserviceId, save.MicroserviceId)
	}
}

func TestListAllSavesByMicroservice_FilterValidFalse(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	ms := app.Microservice{
		MicroserviceId: uuid.New(),
		MSName:         "testms6",
		CreatedBy:      uuid.New(),
		Created:        time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&ms).Error)
	cred := app.Cred{
		CredId:  uuid.New(),
		DBName:  "testms6db",
		Created: time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&cred).Error)
	testutils.InsertRoleCredMS(t, TestApp.DB, ms.MicroserviceId, cred.CredId, "admin", ms.CreatedBy)
	now := time.Now()
	testutils.InsertSaveRecord(t, TestApp.DB, app.SaveRecord{
		SaveId:         uuid.New(),
		MicroserviceId: ms.MicroserviceId,
		CredId:         cred.CredId,
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
		MicroserviceId: ms.MicroserviceId,
		CredId:         cred.CredId,
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
		MicroserviceId: ms.MicroserviceId,
		CredId:         cred.CredId,
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
		MicroserviceId: ms.MicroserviceId,
		CredId:         cred.CredId,
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
	url := fmt.Sprintf("/admin/microservice/%s/saves?valid=false", ms.MicroserviceId.String())
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	saves, noOfSaves := testutils.ExtractSavesList(t, w.Body.Bytes())
	require.Equal(t, 2, noOfSaves)
	for _, save := range saves {
		require.False(t, save.Valid)
		require.Equal(t, ms.MicroserviceId, save.MicroserviceId)
	}
}

func TestListAllSavesByMicroservice_FilterValidTrue_NoRecords(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	ms := app.Microservice{
		MicroserviceId: uuid.New(),
		MSName:         "testms7",
		CreatedBy:      uuid.New(),
		Created:        time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&ms).Error)
	cred := app.Cred{
		CredId:  uuid.New(),
		DBName:  "testms7db",
		Created: time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&cred).Error)
	testutils.InsertRoleCredMS(t, TestApp.DB, ms.MicroserviceId, cred.CredId, "admin", ms.CreatedBy)
	now := time.Now()
	testutils.InsertSaveRecord(t, TestApp.DB, app.SaveRecord{
		SaveId:         uuid.New(),
		MicroserviceId: ms.MicroserviceId,
		CredId:         cred.CredId,
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
	url := fmt.Sprintf("/admin/microservice/%s/saves?valid=true", ms.MicroserviceId.String())
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusNotFound, w.Code)
	require.Contains(t, w.Body.String(), "No saves found")
}

func TestListAllSavesByMicroservice_FilterValidFalse_NoRecords(t *testing.T) {
	testutils.ResetPostgresDB(t, TestApp)
	ms := app.Microservice{
		MicroserviceId: uuid.New(),
		MSName:         "testms8",
		CreatedBy:      uuid.New(),
		Created:        time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&ms).Error)
	cred := app.Cred{
		CredId:  uuid.New(),
		DBName:  "testms8db",
		Created: time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&cred).Error)
	testutils.InsertRoleCredMS(t, TestApp.DB, ms.MicroserviceId, cred.CredId, "admin", ms.CreatedBy)
	now := time.Now()
	testutils.InsertSaveRecord(t, TestApp.DB, app.SaveRecord{
		SaveId:         uuid.New(),
		MicroserviceId: ms.MicroserviceId,
		CredId:         cred.CredId,
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
	url := fmt.Sprintf("/admin/microservice/%s/saves?valid=false", ms.MicroserviceId.String())
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("y-access-token", token)
	w := httptest.NewRecorder()
	TestApp.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusNotFound, w.Code)
	require.Contains(t, w.Body.String(), "No saves found")
}
