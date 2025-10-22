package unit

import (
	"errors"
	"github.com/cliveyg/poptape-admin/utils"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
)

func TestWipeMicroservice_InvalidUUID(t *testing.T) {
	a, _, _ := testutils.SetupAppWithMockDBAndHooks(t)
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	c.Request = httptest.NewRequest("POST", "/admin/wipe/ms/not-a-uuid", nil)
	c.Params = gin.Params{{Key: "msId", Value: "not-a-uuid"}}
	a.WipeMicroservice(c)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, "Bad request", resp["message"])
}

func TestWipeMicroservice_CredsNotFound(t *testing.T) {
	a, mock, _ := testutils.SetupAppWithMockDBAndHooks(t)
	msId := uuid.New().String()
	mock.ExpectQuery(`SELECT creds\.\* FROM "role_cred_ms" join creds on creds\.cred_id = role_cred_ms\.cred_id WHERE role_cred_ms\.microservice_id = \$1 ORDER BY "role_cred_ms"\."cred_id" LIMIT \$2`).
		WithArgs(msId, 1).
		WillReturnError(gorm.ErrRecordNotFound)
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	c.Request = httptest.NewRequest("POST", "/admin/wipe/ms/"+msId, nil)
	c.Params = gin.Params{{Key: "msId", Value: msId}}
	a.WipeMicroservice(c)
	assert.Equal(t, http.StatusNotFound, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, "No creds found", resp["message"])
}

func TestWipeMicroservice_CredsDBError(t *testing.T) {
	a, mock, _ := testutils.SetupAppWithMockDBAndHooks(t)
	msId := uuid.New().String()
	mock.ExpectQuery(`SELECT creds\.\* FROM "role_cred_ms" join creds on creds\.cred_id = role_cred_ms\.cred_id WHERE role_cred_ms\.microservice_id = \$1 ORDER BY "role_cred_ms"\."cred_id" LIMIT \$2`).
		WithArgs(msId, 1).
		WillReturnError(errors.New("some db error"))
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	c.Request = httptest.NewRequest("POST", "/admin/wipe/ms/"+msId, nil)
	c.Params = gin.Params{{Key: "msId", Value: msId}}
	a.WipeMicroservice(c)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, "Something went nope", resp["message"])
}

func TestWipeMicroservice_DecryptError(t *testing.T) {
	a, mock, _ := testutils.SetupAppWithMockDBAndHooks(t)
	msId := uuid.New().String()
	cred := app.Cred{
		CredId:     uuid.New(),
		DBName:     "db",
		Type:       "postgres",
		DBPassword: "bad_encrypted_password",
	}
	rows := sqlmock.NewRows([]string{
		"cred_id", "db_name", "type", "db_password", "host", "url", "db_port",
		"db_username", "last_used", "last_used_by", "created_by", "created",
	}).AddRow(cred.CredId, cred.DBName, cred.Type, cred.DBPassword, "", "", "", "", time.Now(), "", uuid.New(), time.Now())
	mock.ExpectQuery(`SELECT creds\.\* FROM "role_cred_ms" join creds on creds\.cred_id = role_cred_ms\.cred_id WHERE role_cred_ms\.microservice_id = \$1 ORDER BY "role_cred_ms"\."cred_id" LIMIT \$2`).
		WithArgs(msId, 1).
		WillReturnRows(rows)
	origDecrypt := utils.Decrypt
	utils.Decrypt = func(enc string, key, nonce []byte) ([]byte, error) {
		return nil, errors.New("decrypt fail")
	}
	defer func() { utils.Decrypt = origDecrypt }()
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	c.Request = httptest.NewRequest("POST", "/admin/wipe/ms/"+msId, nil)
	c.Params = gin.Params{{Key: "msId", Value: msId}}
	a.WipeMicroservice(c)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, "Error decrypting password from creds", resp["message"])
}

func TestWipeMicroservice_PostgresDeleteAllRecsError(t *testing.T) {
	a, mock, hooks := testutils.SetupAppWithMockDBAndHooks(t)
	msId := uuid.New().String()
	cred := app.Cred{
		CredId:     uuid.New(),
		DBName:     "db",
		Type:       "postgres",
		DBPassword: "good_encrypted_pw",
	}
	rows := sqlmock.NewRows([]string{
		"cred_id", "db_name", "type", "db_password", "host", "url", "db_port",
		"db_username", "last_used", "last_used_by", "created_by", "created",
	}).AddRow(cred.CredId, cred.DBName, cred.Type, cred.DBPassword, "", "", "", "", time.Now(), "", uuid.New(), time.Now())
	mock.ExpectQuery(`SELECT creds\.\* FROM "role_cred_ms" join creds on creds\.cred_id = role_cred_ms\.cred_id WHERE role_cred_ms\.microservice_id = \$1 ORDER BY "role_cred_ms"\."cred_id" LIMIT \$2`).
		WithArgs(msId, 1).
		WillReturnRows(rows)
	origDecrypt := utils.Decrypt
	utils.Decrypt = func(enc string, key, nonce []byte) ([]byte, error) {
		return []byte("pw"), nil
	}
	defer func() { utils.Decrypt = origDecrypt }()
	hooks.PostgresDeleteAllRecsFunc = func(crd *app.Cred, pw *[]byte) (int, error) {
		return http.StatusInternalServerError, errors.New("delete error")
	}
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	c.Request = httptest.NewRequest("POST", "/admin/wipe/ms/"+msId, nil)
	c.Params = gin.Params{{Key: "msId", Value: msId}}
	a.WipeMicroservice(c)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, "delete error", resp["message"])
}

func TestWipeMicroservice_MongoDropError(t *testing.T) {
	a, mock, hooks := testutils.SetupAppWithMockDBAndHooks(t)
	msId := uuid.New().String()
	cred := app.Cred{
		CredId:     uuid.New(),
		DBName:     "db",
		Type:       "mongo",
		DBPassword: "good_encrypted_pw",
	}
	rows := sqlmock.NewRows([]string{
		"cred_id", "db_name", "type", "db_password", "host", "url", "db_port",
		"db_username", "last_used", "last_used_by", "created_by", "created",
	}).AddRow(cred.CredId, cred.DBName, cred.Type, cred.DBPassword, "", "", "", "", time.Now(), "", uuid.New(), time.Now())
	mock.ExpectQuery(`SELECT creds\.\* FROM "role_cred_ms" join creds on creds\.cred_id = role_cred_ms\.cred_id WHERE role_cred_ms\.microservice_id = \$1 ORDER BY "role_cred_ms"\."cred_id" LIMIT \$2`).
		WithArgs(msId, 1).
		WillReturnRows(rows)
	origDecrypt := utils.Decrypt
	utils.Decrypt = func(enc string, key, nonce []byte) ([]byte, error) {
		return []byte("pw"), nil
	}
	defer func() { utils.Decrypt = origDecrypt }()
	hooks.WriteMongoOutFunc = func(args *app.WriteMongoArgs) (string, error) {
		return "", errors.New("mongo drop fail")
	}
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	c.Request = httptest.NewRequest("POST", "/admin/wipe/ms/"+msId, nil)
	c.Params = gin.Params{{Key: "msId", Value: msId}}
	a.WipeMicroservice(c)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, "Failed to drop all collections before restore", resp["message"])
}

func TestWipeMicroservice_HappyPath_Postgres(t *testing.T) {
	a, mock, hooks := testutils.SetupAppWithMockDBAndHooks(t)
	msId := uuid.New().String()
	cred := app.Cred{
		CredId:     uuid.New(),
		DBName:     "db",
		Type:       "postgres",
		DBPassword: "good_encrypted_pw",
	}
	rows := sqlmock.NewRows([]string{
		"cred_id", "db_name", "type", "db_password", "host", "url", "db_port",
		"db_username", "last_used", "last_used_by", "created_by", "created",
	}).AddRow(cred.CredId, cred.DBName, cred.Type, cred.DBPassword, "", "", "", "", time.Now(), "", uuid.New(), time.Now())
	mock.ExpectQuery(`SELECT creds\.\* FROM "role_cred_ms" join creds on creds\.cred_id = role_cred_ms\.cred_id WHERE role_cred_ms\.microservice_id = \$1 ORDER BY "role_cred_ms"\."cred_id" LIMIT \$2`).
		WithArgs(msId, 1).
		WillReturnRows(rows)
	origDecrypt := utils.Decrypt
	utils.Decrypt = func(enc string, key, nonce []byte) ([]byte, error) {
		return []byte("pw"), nil
	}
	defer func() { utils.Decrypt = origDecrypt }()
	hooks.PostgresDeleteAllRecsFunc = func(crd *app.Cred, pw *[]byte) (int, error) {
		return http.StatusOK, nil
	}
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	c.Request = httptest.NewRequest("POST", "/admin/wipe/ms/"+msId, nil)
	c.Params = gin.Params{{Key: "msId", Value: msId}}
	a.WipeMicroservice(c)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, "wibble", resp["message"])
}

func TestWipeMicroservice_HappyPath_Mongo(t *testing.T) {
	a, mock, hooks := testutils.SetupAppWithMockDBAndHooks(t)
	msId := uuid.New().String()
	cred := app.Cred{
		CredId:     uuid.New(),
		DBName:     "db",
		Type:       "mongo",
		DBPassword: "good_encrypted_pw",
	}
	rows := sqlmock.NewRows([]string{
		"cred_id", "db_name", "type", "db_password", "host", "url", "db_port",
		"db_username", "last_used", "last_used_by", "created_by", "created",
	}).AddRow(cred.CredId, cred.DBName, cred.Type, cred.DBPassword, "", "", "", "", time.Now(), "", uuid.New(), time.Now())
	mock.ExpectQuery(`SELECT creds\.\* FROM "role_cred_ms" join creds on creds\.cred_id = role_cred_ms\.cred_id WHERE role_cred_ms\.microservice_id = \$1 ORDER BY "role_cred_ms"\."cred_id" LIMIT \$2`).
		WithArgs(msId, 1).
		WillReturnRows(rows)
	origDecrypt := utils.Decrypt
	utils.Decrypt = func(enc string, key, nonce []byte) ([]byte, error) {
		return []byte("pw"), nil
	}
	defer func() { utils.Decrypt = origDecrypt }()
	hooks.WriteMongoOutFunc = func(args *app.WriteMongoArgs) (string, error) {
		return "OK", nil
	}
	w := testutils.NewTestResponseRecorder()
	c := testutils.NewTestGinContext(w)
	c.Request = httptest.NewRequest("POST", "/admin/wipe/ms/"+msId, nil)
	c.Params = gin.Params{{Key: "msId", Value: msId}}
	a.WipeMicroservice(c)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := testutils.ExtractJSONResponse(t, w)
	assert.Equal(t, "wibble", resp["message"])
}
