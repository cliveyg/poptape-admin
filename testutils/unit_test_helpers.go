package testutils

import (
	"database/sql"
	"github.com/cliveyg/poptape-admin/app"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"
	"gorm.io/gorm"
	"io"
	"net/http/httptest"
)

// MockDB implements app.DBInterface for use in unit tests. All methods are stubbed for testify/mock.
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

// ------ Test helpers -------

func CreateTestLogger() *zerolog.Logger {
	logger := zerolog.New(io.Discard)
	return &logger
}

func CreateTestGinContextWithUser(user app.User) (*gin.Context, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("user", user)
	return c, w
}

func NewTestResponseRecorder() *httptest.ResponseRecorder {
	return httptest.NewRecorder()
}

func NewTestGinContext(w *httptest.ResponseRecorder) *gin.Context {
	c, _ := gin.CreateTestContext(w)
	return c
}
