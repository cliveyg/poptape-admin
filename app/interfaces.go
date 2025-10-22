package app

import (
	"context"
	"database/sql"
	"gorm.io/gorm"
	"io"
	"os/exec"
)

//-----------------------------------------------------------------------------
// DBInterface interface
//-----------------------------------------------------------------------------

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

func NewGormDB(db *gorm.DB) *GormDB {
	return &GormDB{db: db}
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

//-----------------------------------------------------------------------------
// CommandRunner interface
//-----------------------------------------------------------------------------

type CommandRunner interface {
	Command(name string, args ...string) Cmd
}

// Cmd abstracts exec.Cmd for testability and mocking.
type Cmd interface {
	Start() error
	Run() error
	Wait() error
	StdoutPipe() (io.ReadCloser, error)
	StderrPipe() (io.ReadCloser, error)
	StdinPipe() (io.WriteCloser, error)
	SetEnv(env []string)
	SetStdout(w io.Writer)
	SetStderr(w io.Writer)
	SetStdin(r io.Reader)
}

// RealCommandRunner is the production implementation using os/exec.
type RealCommandRunner struct{}

func (r *RealCommandRunner) Command(name string, args ...string) Cmd {
	return &RealCmd{cmd: exec.Command(name, args...)}
}

type RealCmd struct {
	cmd *exec.Cmd
}

func (c *RealCmd) Start() error                       { return c.cmd.Start() }
func (c *RealCmd) Run() error                         { return c.cmd.Run() }
func (c *RealCmd) Wait() error                        { return c.cmd.Wait() }
func (c *RealCmd) StdoutPipe() (io.ReadCloser, error) { return c.cmd.StdoutPipe() }
func (c *RealCmd) StderrPipe() (io.ReadCloser, error) { return c.cmd.StderrPipe() }
func (c *RealCmd) StdinPipe() (io.WriteCloser, error) { return c.cmd.StdinPipe() }
func (c *RealCmd) SetEnv(env []string)                { c.cmd.Env = env }
func (c *RealCmd) SetStdout(w io.Writer)              { c.cmd.Stdout = w }
func (c *RealCmd) SetStderr(w io.Writer)              { c.cmd.Stderr = w }
func (c *RealCmd) SetStdin(r io.Reader)               { c.cmd.Stdin = r }

//-----------------------------------------------------------------------------
// Hooks interface - this is so we can unit test with mocking of functions.
// Any functions you wish to mock must be called with a.Hooks.FunctionName
// in the app so we can use a TestApp and swap out the function to be mocked.
// This then enables us to mock Functions for unit tests etc. Bit cludgy but
// golang doesn't allow monkey patching and this is the least bad option. See
// the testutils unit_test_helpers.go file for actual mocks
//-----------------------------------------------------------------------------

type Hooks interface {
	PrepSaveRestore(args *PrepSaveRestoreArgs) *PrepSaveRestoreResult
	BackupPostgres(args *BackupDBArgs) error
	BackupMongo(args *BackupDBArgs) error
	RestorePostgres(args *RestoreDBArgs) (int, string)
	RestoreMongo(args *RestoreDBArgs) (int, string)
	WriteSQLOut(args *WriteSQLArgs) (any, error)
	WriteMongoOut(args *WriteMongoArgs) (string, error)
	PostgresDeleteAllRecs(crd *Cred, pw *[]byte) (int, error)
	DeleteGridFSBySaveID(ctx *context.Context, saveId, DBName string) error
	UserHasCorrectAccess(svRec *SaveRecord, u *User) (int, error)
	// Add more methods you want to mock/test in the future
}
