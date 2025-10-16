package testutils

import (
	"database/sql"

	"gorm.io/gorm"
)

// ChainableMockDB implements DBInterface for unit tests with chainable GORM API
type ChainableMockDB struct {
	FindError  error
	OrderError error
}

// Chainable methods: return *gorm.DB with Statement set to avoid panics on further chaining
func (m *ChainableMockDB) Order(value interface{}) *gorm.DB {
	db := &gorm.DB{Statement: &gorm.Statement{DB: &gorm.DB{}}}
	if m.OrderError != nil {
		db.Error = m.OrderError
	}
	return db
}
func (m *ChainableMockDB) Where(query interface{}, args ...interface{}) *gorm.DB {
	return &gorm.DB{Statement: &gorm.Statement{DB: &gorm.DB{}}}
}
func (m *ChainableMockDB) Limit(limit int) *gorm.DB {
	return &gorm.DB{Statement: &gorm.Statement{DB: &gorm.DB{}}}
}
func (m *ChainableMockDB) Offset(offset int) *gorm.DB {
	return &gorm.DB{Statement: &gorm.Statement{DB: &gorm.DB{}}}
}
func (m *ChainableMockDB) Group(name string) *gorm.DB {
	return &gorm.DB{Statement: &gorm.Statement{DB: &gorm.DB{}}}
}
func (m *ChainableMockDB) Table(name string) *gorm.DB {
	return &gorm.DB{Statement: &gorm.Statement{DB: &gorm.DB{}}}
}
func (m *ChainableMockDB) Select(query interface{}, args ...interface{}) *gorm.DB {
	return &gorm.DB{Statement: &gorm.Statement{DB: &gorm.DB{}}}
}
func (m *ChainableMockDB) Joins(query string, args ...interface{}) *gorm.DB {
	return &gorm.DB{Statement: &gorm.Statement{DB: &gorm.DB{}}}
}
func (m *ChainableMockDB) Preload(query string, args ...interface{}) *gorm.DB {
	return &gorm.DB{Statement: &gorm.Statement{DB: &gorm.DB{}}}
}

// Terminal methods: return *gorm.DB with error for handler logic
func (m *ChainableMockDB) Find(dest interface{}, conds ...interface{}) *gorm.DB {
	return &gorm.DB{Error: m.FindError, Statement: &gorm.Statement{DB: &gorm.DB{}}}
}
func (m *ChainableMockDB) First(dest interface{}, conds ...interface{}) *gorm.DB {
	return &gorm.DB{Error: m.FindError, Statement: &gorm.Statement{DB: &gorm.DB{}}}
}

// --- All other DBInterface methods, panic if called by mistake ---
func (m *ChainableMockDB) Create(value interface{}) *gorm.DB { panic("not implemented") }
func (m *ChainableMockDB) Delete(value interface{}, conds ...interface{}) *gorm.DB {
	panic("not implemented")
}
func (m *ChainableMockDB) Model(value interface{}) *gorm.DB                 { panic("not implemented") }
func (m *ChainableMockDB) Update(column string, value interface{}) *gorm.DB { panic("not implemented") }
func (m *ChainableMockDB) Exec(sql string, values ...interface{}) *gorm.DB  { panic("not implemented") }
func (m *ChainableMockDB) Migrator() gorm.Migrator                          { panic("not implemented") }
func (m *ChainableMockDB) Save(value interface{}) *gorm.DB                  { panic("not implemented") }
func (m *ChainableMockDB) Set(name string, value interface{}) *gorm.DB      { panic("not implemented") }
func (m *ChainableMockDB) Transaction(fc func(tx *gorm.DB) error, opts ...*sql.TxOptions) error {
	panic("not implemented")
}
func (m *ChainableMockDB) Association(column string) *gorm.Association    { panic("not implemented") }
func (m *ChainableMockDB) Raw(sql string, values ...interface{}) *gorm.DB { panic("not implemented") }
func (m *ChainableMockDB) Scan(dest interface{}) *gorm.DB                 { panic("not implemented") }
