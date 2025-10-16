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
		MSName:         testutils.UniqueName("testms"),
		CreatedBy:      uuid.New(),
		Created:        time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&ms).Error)
	cred := app.Cred{
		CredId:     uuid.New(),
		DBName:     testutils.UniqueName("testmsdb"),
		DBUsername: testutils.UniqueName("user"),
		URL:        testutils.UniqueName("url"),
		Created:    time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&cred).Error)
	testutils.InsertRoleCredMS(t, TestApp.DB, ms.MicroserviceId, cred.CredId, testutils.UniqueName("admin"), ms.CreatedBy)

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
		MSName:         testutils.UniqueName("testms2"),
		CreatedBy:      uuid.New(),
		Created:        time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&ms).Error)
	cred := app.Cred{
		CredId:     uuid.New(),
		DBName:     testutils.UniqueName("testms2db"),
		DBUsername: testutils.UniqueName("user"),
		URL:        testutils.UniqueName("url"),
		Created:    time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&cred).Error)
	roleName := testutils.UniqueName("admin")
	testutils.InsertRoleCredMS(t, TestApp.DB, ms.MicroserviceId, cred.CredId, roleName, ms.CreatedBy)
	saveID := uuid.New()
	now := time.Now()
	testutils.InsertSaveRecord(t, TestApp.DB, app.SaveRecord{
		SaveId:         saveID,
		MicroserviceId: ms.MicroserviceId,
		CredId:         cred.CredId,
		DBName:         cred.DBName,
		Table:          testutils.UniqueName("testtable"),
		SavedBy:        testutils.UniqueName("tester"),
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
		MSName:         testutils.UniqueName("targetms"),
		CreatedBy:      uuid.New(),
		Created:        time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&ms).Error)
	otherMS := app.Microservice{
		MicroserviceId: uuid.New(),
		MSName:         testutils.UniqueName("otherms"),
		CreatedBy:      uuid.New(),
		Created:        time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&otherMS).Error)
	cred := app.Cred{
		CredId:     uuid.New(),
		DBName:     testutils.UniqueName("targetmsdb"),
		DBUsername: testutils.UniqueName("user"),
		URL:        testutils.UniqueName("url"),
		Created:    time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&cred).Error)
	otherCred := app.Cred{
		CredId:     uuid.New(),
		DBName:     testutils.UniqueName("othermsdb"),
		DBUsername: testutils.UniqueName("user"),
		URL:        testutils.UniqueName("url"),
		Created:    time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&otherCred).Error)
	roleName := testutils.UniqueName("admin")
	otherRoleName := testutils.UniqueName("admin")
	testutils.InsertRoleCredMS(t, TestApp.DB, ms.MicroserviceId, cred.CredId, roleName, ms.CreatedBy)
	testutils.InsertRoleCredMS(t, TestApp.DB, otherMS.MicroserviceId, otherCred.CredId, otherRoleName, otherMS.CreatedBy)
	saveID := uuid.New()
	otherSaveID := uuid.New()
	now := time.Now()
	testutils.InsertSaveRecord(t, TestApp.DB, app.SaveRecord{
		SaveId:         otherSaveID,
		MicroserviceId: otherMS.MicroserviceId,
		CredId:         otherCred.CredId,
		DBName:         otherCred.DBName,
		Table:          testutils.UniqueName("othertable"),
		SavedBy:        testutils.UniqueName("tester"),
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
		DBName:         cred.DBName,
		Table:          testutils.UniqueName("testtable"),
		SavedBy:        testutils.UniqueName("tester"),
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
		MSName:         testutils.UniqueName("testms4"),
		CreatedBy:      uuid.New(),
		Created:        time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&ms).Error)
	cred := app.Cred{
		CredId:     uuid.New(),
		DBName:     testutils.UniqueName("testms4db"),
		DBUsername: testutils.UniqueName("user"),
		URL:        testutils.UniqueName("url"),
		Created:    time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&cred).Error)
	roleName := testutils.UniqueName("admin")
	testutils.InsertRoleCredMS(t, TestApp.DB, ms.MicroserviceId, cred.CredId, roleName, ms.CreatedBy)

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
		MSName:         testutils.UniqueName("testms5"),
		CreatedBy:      uuid.New(),
		Created:        time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&ms).Error)
	cred := app.Cred{
		CredId:     uuid.New(),
		DBName:     testutils.UniqueName("testms5db"),
		DBUsername: testutils.UniqueName("user"),
		URL:        testutils.UniqueName("url"),
		Created:    time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&cred).Error)
	roleName := testutils.UniqueName("admin")
	testutils.InsertRoleCredMS(t, TestApp.DB, ms.MicroserviceId, cred.CredId, roleName, ms.CreatedBy)
	now := time.Now()
	testutils.InsertSaveRecord(t, TestApp.DB, app.SaveRecord{
		SaveId:         uuid.New(),
		MicroserviceId: ms.MicroserviceId,
		CredId:         cred.CredId,
		DBName:         testutils.UniqueName("validdb1"),
		Table:          testutils.UniqueName("table1"),
		SavedBy:        testutils.UniqueName("tester"),
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
		DBName:         testutils.UniqueName("validdb2"),
		Table:          testutils.UniqueName("table2"),
		SavedBy:        testutils.UniqueName("tester"),
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
		DBName:         testutils.UniqueName("invaliddb"),
		Table:          testutils.UniqueName("table3"),
		SavedBy:        testutils.UniqueName("tester"),
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
		MSName:         testutils.UniqueName("testms6"),
		CreatedBy:      uuid.New(),
		Created:        time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&ms).Error)
	cred := app.Cred{
		CredId:     uuid.New(),
		DBName:     testutils.UniqueName("testms6db"),
		DBUsername: testutils.UniqueName("user"),
		URL:        testutils.UniqueName("url"),
		Created:    time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&cred).Error)
	roleName := testutils.UniqueName("admin")
	testutils.InsertRoleCredMS(t, TestApp.DB, ms.MicroserviceId, cred.CredId, roleName, ms.CreatedBy)
	now := time.Now()
	testutils.InsertSaveRecord(t, TestApp.DB, app.SaveRecord{
		SaveId:         uuid.New(),
		MicroserviceId: ms.MicroserviceId,
		CredId:         cred.CredId,
		DBName:         testutils.UniqueName("validdb1"),
		Table:          testutils.UniqueName("table1"),
		SavedBy:        testutils.UniqueName("tester"),
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
		DBName:         testutils.UniqueName("invaliddb1"),
		Table:          testutils.UniqueName("table2"),
		SavedBy:        testutils.UniqueName("tester"),
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
		DBName:         testutils.UniqueName("validdb2"),
		Table:          testutils.UniqueName("table3"),
		SavedBy:        testutils.UniqueName("tester"),
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
		DBName:         testutils.UniqueName("invaliddb2"),
		Table:          testutils.UniqueName("table4"),
		SavedBy:        testutils.UniqueName("tester"),
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
		MSName:         testutils.UniqueName("testms7"),
		CreatedBy:      uuid.New(),
		Created:        time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&ms).Error)
	cred := app.Cred{
		CredId:     uuid.New(),
		DBName:     testutils.UniqueName("testms7db"),
		DBUsername: testutils.UniqueName("user"),
		URL:        testutils.UniqueName("url"),
		Created:    time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&cred).Error)
	roleName := testutils.UniqueName("admin")
	testutils.InsertRoleCredMS(t, TestApp.DB, ms.MicroserviceId, cred.CredId, roleName, ms.CreatedBy)
	now := time.Now()
	testutils.InsertSaveRecord(t, TestApp.DB, app.SaveRecord{
		SaveId:         uuid.New(),
		MicroserviceId: ms.MicroserviceId,
		CredId:         cred.CredId,
		DBName:         testutils.UniqueName("invaliddb1"),
		Table:          testutils.UniqueName("table1"),
		SavedBy:        testutils.UniqueName("tester"),
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
		MSName:         testutils.UniqueName("testms8"),
		CreatedBy:      uuid.New(),
		Created:        time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&ms).Error)
	cred := app.Cred{
		CredId:     uuid.New(),
		DBName:     testutils.UniqueName("testms8db"),
		DBUsername: testutils.UniqueName("user"),
		URL:        testutils.UniqueName("url"),
		Created:    time.Now(),
	}
	require.NoError(t, TestApp.DB.Create(&cred).Error)
	roleName := testutils.UniqueName("admin")
	testutils.InsertRoleCredMS(t, TestApp.DB, ms.MicroserviceId, cred.CredId, roleName, ms.CreatedBy)
	now := time.Now()
	testutils.InsertSaveRecord(t, TestApp.DB, app.SaveRecord{
		SaveId:         uuid.New(),
		MicroserviceId: ms.MicroserviceId,
		CredId:         cred.CredId,
		DBName:         testutils.UniqueName("validdb1"),
		Table:          testutils.UniqueName("table1"),
		SavedBy:        testutils.UniqueName("tester"),
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
