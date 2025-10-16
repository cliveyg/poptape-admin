package testutils

import (
	"database/sql"
	"gorm.io/gorm"
)

// This struct will be returned by all chainable methods in your mock.
type GormDBMock struct {
	Error error
}

func (m *GormDBMock) Order(value interface{}) *gorm.DB { return &gorm.DB{Error: m.Error} }
func (m *GormDBMock) Where(query interface{}, args ...interface{}) *gorm.DB {
	return &gorm.DB{Error: m.Error}
}
func (m *GormDBMock) Limit(limit int) *gorm.DB   { return &gorm.DB{Error: m.Error} }
func (m *GormDBMock) Offset(offset int) *gorm.DB { return &gorm.DB{Error: m.Error} }
func (m *GormDBMock) Group(name string) *gorm.DB { return &gorm.DB{Error: m.Error} }
func (m *GormDBMock) Table(name string) *gorm.DB { return &gorm.DB{Error: m.Error} }
func (m *GormDBMock) Select(query interface{}, args ...interface{}) *gorm.DB {
	return &gorm.DB{Error: m.Error}
}
func (m *GormDBMock) Joins(query string, args ...interface{}) *gorm.DB {
	return &gorm.DB{Error: m.Error}
}
func (m *GormDBMock) Preload(query string, args ...interface{}) *gorm.DB {
	return &gorm.DB{Error: m.Error}
}

// Terminal methods
func (m *GormDBMock) Find(dest interface{}, conds ...interface{}) *gorm.DB {
	return &gorm.DB{Error: m.Error}
}
func (m *GormDBMock) First(dest interface{}, conds ...interface{}) *gorm.DB {
	return &gorm.DB{Error: m.Error}
}

// All other DBInterface methods panic if called
func (m *GormDBMock) Create(value interface{}) *gorm.DB { panic("not implemented") }
func (m *GormDBMock) Delete(value interface{}, conds ...interface{}) *gorm.DB {
	panic("not implemented")
}
func (m *GormDBMock) Model(value interface{}) *gorm.DB                 { panic("not implemented") }
func (m *GormDBMock) Update(column string, value interface{}) *gorm.DB { panic("not implemented") }
func (m *GormDBMock) Exec(sql string, values ...interface{}) *gorm.DB  { panic("not implemented") }
func (m *GormDBMock) Migrator() gorm.Migrator                          { panic("not implemented") }
func (m *GormDBMock) Save(value interface{}) *gorm.DB                  { panic("not implemented") }
func (m *GormDBMock) Set(name string, value interface{}) *gorm.DB      { panic("not implemented") }
func (m *GormDBMock) Transaction(fc func(tx *gorm.DB) error, opts ...*sql.TxOptions) error {
	panic("not implemented")
}
func (m *GormDBMock) Association(column string) *gorm.Association    { panic("not implemented") }
func (m *GormDBMock) Raw(sql string, values ...interface{}) *gorm.DB { panic("not implemented") }
func (m *GormDBMock) Scan(dest interface{}) *gorm.DB                 { panic("not implemented") }
