package testutils

import (
	"database/sql"
	"gorm.io/gorm"
)

// MockDB implements app.DBInterface for use in tests.
type MockDB struct {
	// set these fields in each test to simulate errors
	FirstError   error
	FindError    error
	CreateError  error
	DeleteError  error
	WhereError   error
	PreloadError error
	ModelError   error
	UpdateError  error
	ExecError    error
	SaveError    error
	SetError     error
	TableError   error
	SelectError  error
	JoinsError   error
	OrderError   error
	GroupError   error
	LimitError   error
	OffsetError  error
	RawError     error
	ScanError    error

	// can add fields to return custom data
	FindResult  interface{}
	FirstResult interface{}
}

func (m *MockDB) First(dest interface{}, conds ...interface{}) *gorm.DB {
	if m.FirstError != nil {
		return &gorm.DB{Error: m.FirstError}
	}
	// Optionally copy result to dest if set
	if m.FirstResult != nil {
		// Use reflection/copy as needed
	}
	return &gorm.DB{}
}
func (m *MockDB) Find(dest interface{}, conds ...interface{}) *gorm.DB {
	if m.FindError != nil {
		return &gorm.DB{Error: m.FindError}
	}
	if m.FindResult != nil {
		// Use reflection/copy as needed
	}
	return &gorm.DB{}
}
func (m *MockDB) Create(value interface{}) *gorm.DB {
	return &gorm.DB{Error: m.CreateError}
}
func (m *MockDB) Delete(value interface{}, conds ...interface{}) *gorm.DB {
	return &gorm.DB{Error: m.DeleteError}
}
func (m *MockDB) Where(query interface{}, args ...interface{}) *gorm.DB {
	return &gorm.DB{Error: m.WhereError}
}
func (m *MockDB) Preload(query string, args ...interface{}) *gorm.DB {
	return &gorm.DB{Error: m.PreloadError}
}
func (m *MockDB) Model(value interface{}) *gorm.DB {
	return &gorm.DB{Error: m.ModelError}
}
func (m *MockDB) Update(column string, value interface{}) *gorm.DB {
	return &gorm.DB{Error: m.UpdateError}
}
func (m *MockDB) Exec(sql string, values ...interface{}) *gorm.DB {
	return &gorm.DB{Error: m.ExecError}
}
func (m *MockDB) Migrator() gorm.Migrator {
	// Return nil or a mock migrator as needed
	return nil
}
func (m *MockDB) Save(value interface{}) *gorm.DB {
	return &gorm.DB{Error: m.SaveError}
}
func (m *MockDB) Set(name string, value interface{}) *gorm.DB {
	return &gorm.DB{Error: m.SetError}
}
func (m *MockDB) Transaction(fc func(tx *gorm.DB) error, opts ...*sql.TxOptions) error {
	// Optionally simulate transaction error
	return nil
}
func (m *MockDB) Association(column string) *gorm.Association {
	// Optionally mock as needed
	return nil
}
func (m *MockDB) Table(name string) *gorm.DB {
	return &gorm.DB{Error: m.TableError}
}
func (m *MockDB) Select(query interface{}, args ...interface{}) *gorm.DB {
	return &gorm.DB{Error: m.SelectError}
}
func (m *MockDB) Joins(query string, args ...interface{}) *gorm.DB {
	return &gorm.DB{Error: m.JoinsError}
}
func (m *MockDB) Order(value interface{}) *gorm.DB {
	return &gorm.DB{Error: m.OrderError}
}
func (m *MockDB) Group(name string) *gorm.DB {
	return &gorm.DB{Error: m.GroupError}
}
func (m *MockDB) Limit(limit int) *gorm.DB {
	return &gorm.DB{Error: m.LimitError}
}
func (m *MockDB) Offset(offset int) *gorm.DB {
	return &gorm.DB{Error: m.OffsetError}
}
func (m *MockDB) Raw(sql string, values ...interface{}) *gorm.DB {
	return &gorm.DB{Error: m.RawError}
}
func (m *MockDB) Scan(dest interface{}) *gorm.DB {
	return &gorm.DB{Error: m.ScanError}
}
