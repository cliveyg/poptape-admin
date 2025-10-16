package app

import (
	"database/sql"
	"gorm.io/gorm"
)

// DBInterface abstracts gorm.DB for testability and flexibility
type DBInterface interface {
	First(dest interface{}, conds ...interface{}) *gorm.DB
	Find(dest interface{}, conds ...interface{}) *gorm.DB
	Create(value interface{}) *gorm.DB
	Delete(value interface{}, conds ...interface{}) *gorm.DB
	Where(query interface{}, args ...interface{}) *gorm.DB
	Preload(query string, args ...interface{}) *gorm.DB
	Model(value interface{}) *gorm.DB
	Update(column string, value interface{}) *gorm.DB
	Exec(sql string, values ...interface{}) *gorm.DB
	Migrator() gorm.Migrator
	Save(value interface{}) *gorm.DB
	Set(name string, value interface{}) *gorm.DB
	Transaction(fc func(tx *gorm.DB) error, opts ...*sql.TxOptions) error
	Association(column string) *gorm.Association
	Table(name string) *gorm.DB
	Select(query interface{}, args ...interface{}) *gorm.DB
	Joins(query string, args ...interface{}) *gorm.DB
	Order(value interface{}) *gorm.DB
	Group(name string) *gorm.DB
	Limit(limit int) *gorm.DB
	Offset(offset int) *gorm.DB
	Raw(sql string, values ...interface{}) *gorm.DB
	Scan(dest interface{}) *gorm.DB
}

// GormDB implements DBInterface for gorm.DB
type GormDB struct {
	db *gorm.DB
}

func (g *GormDB) First(dest interface{}, conds ...interface{}) *gorm.DB {
	return g.db.First(dest, conds...)
}
func (g *GormDB) Find(dest interface{}, conds ...interface{}) *gorm.DB {
	return g.db.Find(dest, conds...)
}
func (g *GormDB) Create(value interface{}) *gorm.DB {
	return g.db.Create(value)
}
func (g *GormDB) Delete(value interface{}, conds ...interface{}) *gorm.DB {
	return g.db.Delete(value, conds...)
}
func (g *GormDB) Where(query interface{}, args ...interface{}) *gorm.DB {
	return g.db.Where(query, args...)
}
func (g *GormDB) Preload(query string, args ...interface{}) *gorm.DB {
	return g.db.Preload(query, args...)
}
func (g *GormDB) Model(value interface{}) *gorm.DB {
	return g.db.Model(value)
}
func (g *GormDB) Update(column string, value interface{}) *gorm.DB {
	return g.db.Update(column, value)
}
func (g *GormDB) Exec(sql string, values ...interface{}) *gorm.DB {
	return g.db.Exec(sql, values...)
}
func (g *GormDB) Migrator() gorm.Migrator {
	return g.db.Migrator()
}
func (g *GormDB) Save(value interface{}) *gorm.DB {
	return g.db.Save(value)
}
func (g *GormDB) Set(name string, value interface{}) *gorm.DB {
	return g.db.Set(name, value)
}
func (g *GormDB) Transaction(fc func(tx *gorm.DB) error, opts ...*sql.TxOptions) error {
	return g.db.Transaction(fc, opts...)
}
func (g *GormDB) Association(column string) *gorm.Association {
	return g.db.Association(column)
}
func (g *GormDB) Table(name string) *gorm.DB {
	return g.db.Table(name)
}
func (g *GormDB) Select(query interface{}, args ...interface{}) *gorm.DB {
	return g.db.Select(query, args...)
}
func (g *GormDB) Joins(query string, args ...interface{}) *gorm.DB {
	return g.db.Joins(query, args...)
}
func (g *GormDB) Order(value interface{}) *gorm.DB {
	return g.db.Order(value)
}
func (g *GormDB) Group(name string) *gorm.DB {
	return g.db.Group(name)
}
func (g *GormDB) Limit(limit int) *gorm.DB {
	return g.db.Limit(limit)
}
func (g *GormDB) Offset(offset int) *gorm.DB {
	return g.db.Offset(offset)
}
func (g *GormDB) Raw(sql string, values ...interface{}) *gorm.DB {
	return g.db.Raw(sql, values...)
}
func (g *GormDB) Scan(dest interface{}) *gorm.DB {
	return g.db.Scan(dest)
}
