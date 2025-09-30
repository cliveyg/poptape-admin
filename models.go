package main

import (
	"errors"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"os"
	"time"
)

//-----------------------------------------------------------------------------

type User struct {
	AdminId   uuid.UUID      `json:"admin_id" gorm:"type:uuid;primaryKey;"`
	Username  string         `json:"username" gorm:"unique"`
	Password  []byte         `json:"-"`
	LastLogin time.Time      `json:"last_login"`
	Active    bool           `json:"active" binding:"required"`
	Validated bool           `json:"validated" binding:"required"`
	Roles     []Role         `json:"roles" gorm:"many2many:user_role"`
	Created   time.Time      `json:"created"`
	Updated   time.Time      `json:"updated"`
	Deleted   gorm.DeletedAt `json:"-"`
}

func (u *User) BeforeCreate(_ *gorm.DB) (err error) {
	u.AdminId = uuid.New()
	u.Created = time.Now()
	u.Updated = time.Now()
	u.Active = true
	u.Validated = false
	return
}

func (u *User) BeforeUpdate(tx *gorm.DB) (err error) {

	// if we come from login, update LastLogin
	// then logic to prevent superuser update
	// then set Updated field if we come from
	// anywhere else
	if _, ok := tx.Get("login"); ok {
		u.LastLogin = time.Now()
	} else if u.Username == os.Getenv("SUPERUSER") &&
		os.Getenv("CREATESUPER") != "y" {
		return errors.New("not allowed to edit superuser")
	} else {
		u.Updated = time.Now()
	}
	return
}

func (u *User) BeforeDelete(_ *gorm.DB) (err error) {
	if u.Username == os.Getenv("SUPERUSER") {
		return errors.New("not allowed to delete super user")
	}
	u.Active = false
	u.Updated = time.Now()
	return
}

//-----------------------------------------------------------------------------
// in theory we can have more than one set of creds per microservice that
// is why microservice is in a separate table

type Cred struct {
	CredId     uuid.UUID `json:"cred_id" gorm:"type:uuid;primaryKey;" binding:"-"`
	DBName     string    `json:"db_name" gorm:"unique" binding:"required"`
	Type       string    `json:"type" binding:"required"`
	URL        string    `json:"url" gorm:"unique" binding:"required"`
	Port       string    `json:"port" gorm:"unique" binding:"required"`
	DBUsername string    `json:"db_username" gorm:"unique" binding:"required"`
	DBPassword string    `json:"db_password" binding:"required"`
	LastUsed   time.Time `json:"last_used" binding:"-"`
	LastUsedBy string    `json:"last_used_by"  gorm:"foreignKey:Username" binding:"-"`
	CreatedBy  uuid.UUID `json:"created_by" gorm:"foreignKey:AdminId" binding:"-"`
	Created    time.Time `json:"created" binding:"-"`
}

func (c *Cred) BeforeCreate(_ *gorm.DB) (err error) {
	c.CredId = uuid.New()
	c.Created = time.Now()
	return
}

//-----------------------------------------------------------------------------

type MsIn struct {
	MSName string `json:"ms_name" binding:"required" gorm:"unique"`
}

//-----------------------------------------------------------------------------

type Microservice struct {
	MicroserviceId uuid.UUID `json:"microservice_id" gorm:"type:uuid;primaryKey;"`
	MSName         string    `json:"ms_name" binding:"required" gorm:"unique"`
	CreatedBy      uuid.UUID `json:"created_by" binding:"required" gorm:"foreignKey:AdminId"`
	Created        time.Time `json:"created"`
}

func (m *Microservice) BeforeCreate(_ *gorm.DB) (err error) {
	m.MicroserviceId = uuid.New()
	m.Created = time.Now()
	return
}

//-----------------------------------------------------------------------------
// this table links roles to microservices and creds. provides more flexibility

type RoleCredMS struct {
	MicroserviceId uuid.UUID `json:"microservice_id" gorm:"foreignKey:MicroserviceId"`
	CredId         uuid.UUID `json:"cred_id" gorm:"foreignKey:CredId"`
	RoleName       string    `json:"role_name" gorm:"foreignKey:Name"`
	CreatedBy      uuid.UUID `json:"created_by" gorm:"foreignKey:AdminId"`
	Created        time.Time `json:"created"`
}

func (rcm *RoleCredMS) BeforeCreate(_ *gorm.DB) (err error) {
	rcm.Created = time.Now()
	return
}

//-----------------------------------------------------------------------------

type APIPath struct {
	APIPathId      uuid.UUID `json:"api_path_id" gorm:"type:uuid;primaryKey;"`
	MicroserviceId string    `json:"microservice_id" gorm:"foreignKey:MicroserviceId"`
	Path           string    `json:"path"`
	CreatedBy      uuid.UUID `json:"created_by" gorm:"foreignKey:AdminId"`
	Created        time.Time `json:"created"`
}

func (a *APIPath) BeforeCreate(_ *gorm.DB) (err error) {
	a.APIPathId = uuid.New()
	a.Created = time.Now()
	return
}

//-----------------------------------------------------------------------------

type Login struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

//-----------------------------------------------------------------------------

type Signup struct {
	Username        string `json:"username" binding:"required"`
	Password        string `json:"password" binding:"required"`
	ConfirmPassword string `json:"confirm_password" binding:"required"`
}

//-----------------------------------------------------------------------------

type Role struct {
	Name    string    `json:"name" gorm:"type:string;primaryKey"`
	Created time.Time `json:"-"`
}

func (r *Role) BeforeCreate(_ *gorm.DB) (err error) {
	r.Created = time.Now()
	return
}

//-----------------------------------------------------------------------------

type DBTables struct {
	DBTableId      uuid.UUID `json:"db_table_id" gorm:"type:uuid;primaryKey;"`
	MicroserviceId uuid.UUID `json:"microservice_id" gorm:"foreignKey:MicroserviceId" binding:"required"`
	CredId         uuid.UUID `json:"cred_id" gorm:"foreignKey:CredId" binding:"required"`
	TableDesc      string    `json:"table_description" binding:"required"`
	TableSQL       string    `json:"table_sql" binding:"required"`
}
