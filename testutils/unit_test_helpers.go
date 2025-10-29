package testutils

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"github.com/cliveyg/poptape-admin/app"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/gridfs"
	"gorm.io/gorm"
	"io"
	"net/http"
	"net/http/httptest"
	"time"
)

//-----------------------------------------------------------------------------
// MockDB implements app.DBInterface for use in unit tests.
// All methods are stubbed for testify/mock.
//-----------------------------------------------------------------------------

type MockDB struct {
	mock.Mock
}

func (m *MockDB) First(dest interface{}, conds ...interface{}) *gorm.DB {
	args := m.Called(dest, conds)
	return args.Get(0).(*gorm.DB)
}
func (m *MockDB) Find(dest interface{}, conds ...interface{}) *gorm.DB {
	args := m.Called(dest, conds)
	return args.Get(0).(*gorm.DB)
}
func (m *MockDB) Create(value interface{}) *gorm.DB {
	args := m.Called(value)
	return args.Get(0).(*gorm.DB)
}
func (m *MockDB) Delete(value interface{}, conds ...interface{}) *gorm.DB {
	args := m.Called(value, conds)
	return args.Get(0).(*gorm.DB)
}
func (m *MockDB) Where(query interface{}, args_ ...interface{}) *gorm.DB {
	args := m.Called(query, args_)
	return args.Get(0).(*gorm.DB)
}
func (m *MockDB) Preload(query string, args_ ...interface{}) *gorm.DB {
	args := m.Called(query, args_)
	return args.Get(0).(*gorm.DB)
}
func (m *MockDB) Model(value interface{}) *gorm.DB {
	args := m.Called(value)
	return args.Get(0).(*gorm.DB)
}
func (m *MockDB) Update(column string, value interface{}) *gorm.DB {
	args := m.Called(column, value)
	return args.Get(0).(*gorm.DB)
}
func (m *MockDB) Exec(sql string, values ...interface{}) *gorm.DB {
	args := m.Called(sql, values)
	return args.Get(0).(*gorm.DB)
}
func (m *MockDB) Migrator() gorm.Migrator {
	args := m.Called()
	return args.Get(0).(gorm.Migrator)
}
func (m *MockDB) Save(value interface{}) *gorm.DB {
	args := m.Called(value)
	return args.Get(0).(*gorm.DB)
}
func (m *MockDB) Set(name string, value interface{}) *gorm.DB {
	args := m.Called(name, value)
	return args.Get(0).(*gorm.DB)
}
func (m *MockDB) Transaction(fc func(tx *gorm.DB) error, opts ...*sql.TxOptions) error {
	args := m.Called(fc, opts)
	return args.Error(0)
}
func (m *MockDB) Association(column string) *gorm.Association {
	args := m.Called(column)
	return args.Get(0).(*gorm.Association)
}
func (m *MockDB) Table(name string) *gorm.DB {
	args := m.Called(name)
	return args.Get(0).(*gorm.DB)
}
func (m *MockDB) Select(query interface{}, args_ ...interface{}) *gorm.DB {
	args := m.Called(query, args_)
	return args.Get(0).(*gorm.DB)
}
func (m *MockDB) Joins(query string, args_ ...interface{}) *gorm.DB {
	args := m.Called(query, args_)
	return args.Get(0).(*gorm.DB)
}
func (m *MockDB) Order(value interface{}) *gorm.DB {
	args := m.Called(value)
	return args.Get(0).(*gorm.DB)
}
func (m *MockDB) Group(name string) *gorm.DB {
	args := m.Called(name)
	return args.Get(0).(*gorm.DB)
}
func (m *MockDB) Limit(limit int) *gorm.DB {
	args := m.Called(limit)
	return args.Get(0).(*gorm.DB)
}
func (m *MockDB) Offset(offset int) *gorm.DB {
	args := m.Called(offset)
	return args.Get(0).(*gorm.DB)
}
func (m *MockDB) Raw(sql string, values ...interface{}) *gorm.DB {
	args := m.Called(sql, values)
	return args.Get(0).(*gorm.DB)
}
func (m *MockDB) Scan(dest interface{}) *gorm.DB {
	args := m.Called(dest)
	return args.Get(0).(*gorm.DB)
}

//-----------------------------------------------------------------------------
// logger for tests
//-----------------------------------------------------------------------------

func CreateTestLogger() *zerolog.Logger {
	//logger := zerolog.New(os.Stdout)
	logger := zerolog.New(io.Discard)
	return &logger
}

//-----------------------------------------------------------------------------
// useful gin and http functions
//-----------------------------------------------------------------------------

func NewTestResponseRecorder() *httptest.ResponseRecorder {
	return httptest.NewRecorder()
}

func NewTestGinContext(w *httptest.ResponseRecorder) *gin.Context {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(w)
	return c
}

// SetupCreateUserGinContext returns a Gin context and response recorder for CreateUser.
func SetupCreateUserGinContext(body []byte, token string) (*gin.Context, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = NewRewindableRequest("POST", "/admin/user", body)
	c.Set("token", token)
	return c, w
}

func SetGinParams(c *gin.Context, aId string, rName string) {
	c.Params = gin.Params{
		{Key: "aId", Value: aId},
		{Key: "rName", Value: rName},
	}
}

// CreateGinContextWithUser returns a Gin Context and ResponseRecorder with the given user set.
func CreateGinContextWithUser(user app.User) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("user", user)
	return c, w
}

func SetupJWTHeaderContext(token string) *gin.Context {
	w := NewTestResponseRecorder()
	c := NewTestGinContext(w)
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("y-access-token", token)
	c.Request = req
	return c
}

// NewRewindableRequest creates an *http.Request with a rewindable body
// suitable for Gin handlers that bind multiple times from the same body.
func NewRewindableRequest(method, url string, body []byte) *http.Request {
	req, _ := http.NewRequest(method, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	raw := body // preserve the body for GetBody
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(raw)), nil
	}
	return req
}

//-----------------------------------------------------------------------------
// structs and functions for testing InitialiseMongo function
//-----------------------------------------------------------------------------

type TestCase struct {
	Name         string
	Config       app.MongoConfig
	Factory      func(context.Context, string) (*mongo.Client, error)
	Timeout      time.Duration
	WantErr      bool
	WantClient   bool
	WantAttempts int
	WantSleeps   int
}

// InitialiseMongoWithTimeout is a test helper to inject timeout and start for Mongo connection logic.
// It mirrors app.InitialiseMongo but allows controlling the retry loop for fast, deterministic tests.
func InitialiseMongoWithTimeout(
	a *app.App,
	config app.MongoConfig,
	clientFactory func(context.Context, string) (*mongo.Client, error),
	sleep app.SleepFunc,
	timeout time.Duration,
	start time.Time,
	now func() time.Time, // Add this parameter!
) error {
	var err error
	var client *mongo.Client
	x := 1
	mongoURI := fmt.Sprintf("mongodb://%s:%s@%s:%s/%s?authSource=admin",
		config.Username, config.Password, config.Host, config.Port, config.DBName,
	)

	for now().Sub(start) < timeout {
		a.Log.Debug().Msgf("Trying to connect to MongoDB...[%d]", x)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		client, err = clientFactory(ctx, mongoURI)
		if err == nil {
			cancel()
			break
		}
		a.Log.Error().Err(err)
		cancel()
		sleep(2 * time.Second)
		x++
	}

	if err != nil {
		a.Log.Fatal().Msgf("Failed to connect to MongoDB after %s seconds", timeout)
		return err
	}

	a.Mongo = client
	a.Log.Debug().Msg("Connected to MongoDB successfully ✓")
	return nil
}

//-----------------------------------------------------------------------------
// MockHooks allows overriding functions for unit testing.
//-----------------------------------------------------------------------------

type MockHooks struct {
	PrepSaveRestoreFunc          func(args *app.PrepSaveRestoreArgs) *app.PrepSaveRestoreResult
	BackupPostgresFunc           func(args *app.BackupDBArgs) error
	RestorePostgresFunc          func(args *app.RestoreDBArgs) (int, string)
	BackupMongoFunc              func(args *app.BackupDBArgs) error
	RestoreMongoFunc             func(args *app.RestoreDBArgs) (int, string)
	WriteSQLOutFunc              func(args *app.WriteSQLArgs) (any, error)
	WriteMongoOutFunc            func(args *app.WriteMongoArgs) (string, error)
	PostgresDeleteAllRecsFunc    func(crd *app.Cred, pw *[]byte) (int, error)
	DeleteGridFSBySaveIDFunc     func(ctx *context.Context, saveId, DBName string) error
	UserHasCorrectAccessFunc     func(svRec *app.SaveRecord, u *app.User) (int, error)
	IOCopyFunc                   func(dst io.Writer, src io.Reader) (int64, error)
	CreateGridFSUploadStreamFunc func(db, filename string, metadata map[string]interface{}) (*gridfs.UploadStream, error)
	CopyToGridFSFunc             func(uploadStream *gridfs.UploadStream, stdout io.Reader, logPrefix string) (int64, error)
	SaveWithAutoVersionFunc      func(rec *app.SaveRecord) error
}

//-----------------------------------------------------------------------------
// functions that can be overridden. must match Hooks interface methods
//-----------------------------------------------------------------------------

func (m *MockHooks) PrepSaveRestore(args *app.PrepSaveRestoreArgs) *app.PrepSaveRestoreResult {
	return m.PrepSaveRestoreFunc(args)
}

func (m *MockHooks) BackupPostgres(args *app.BackupDBArgs) error {
	return m.BackupPostgresFunc(args)
}

func (m *MockHooks) RestorePostgres(args *app.RestoreDBArgs) (int, string) {
	return m.RestorePostgresFunc(args)
}

func (m *MockHooks) BackupMongo(args *app.BackupDBArgs) error {
	return m.BackupMongoFunc(args)
}

func (m *MockHooks) RestoreMongo(args *app.RestoreDBArgs) (int, string) {
	return m.RestoreMongoFunc(args)
}

func (m *MockHooks) WriteSQLOut(args *app.WriteSQLArgs) (any, error) {
	return m.WriteSQLOutFunc(args)
}

func (m *MockHooks) WriteMongoOut(args *app.WriteMongoArgs) (string, error) {
	return m.WriteMongoOutFunc(args)
}

func (m *MockHooks) PostgresDeleteAllRecs(crd *app.Cred, pw *[]byte) (int, error) {
	return m.PostgresDeleteAllRecsFunc(crd, pw)
}

func (m *MockHooks) DeleteGridFSBySaveID(ctx *context.Context, saveId, DBName string) error {
	return m.DeleteGridFSBySaveIDFunc(ctx, saveId, DBName)
}

func (m *MockHooks) CopyToGridFS(uploadStream *gridfs.UploadStream, stdout io.Reader, logPrefix string) (int64, error) {
	return m.CopyToGridFSFunc(uploadStream, stdout, logPrefix)
}

func (m *MockHooks) UserHasCorrectAccess(svRec *app.SaveRecord, u *app.User) (int, error) {
	return m.UserHasCorrectAccessFunc(svRec, u)
}

func (m *MockHooks) IOCopy(dst io.Writer, src io.Reader) (int64, error) {
	return m.IOCopyFunc(dst, src)
}

func (m *MockHooks) CreateGridFSUploadStream(db, filename string, metadata map[string]interface{}) (*gridfs.UploadStream, error) {
	return m.CreateGridFSUploadStreamFunc(db, filename, metadata)
}

func (m *MockHooks) SaveWithAutoVersion(rec *app.SaveRecord) error {
	return m.SaveWithAutoVersionFunc(rec)
}
