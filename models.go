package main

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
	"time"
)

//-----------------------------------------------------------------------------

type User struct {
	AdminId   uuid.UUID `json:"admin_id" gorm:"type:uuid;primary_key;"`
	Username  string    `json:"username" gorm:"unique"`
	Password  []byte    `json:"password"`
	LastLogin time.Time `json:"last_login"`
	Active    bool      `json:"active"`
	Validated bool      `json:"validated"`
	Created   time.Time `json:"created"`
}

func (u *User) BeforeCreate(_ *gorm.DB) (err error) {
	u.AdminId = uuid.New()
	u.Created = time.Now()
	u.Active = true
	u.Validated = false
	return
}

//-----------------------------------------------------------------------------

type Cred struct {
	CredId         uuid.UUID `json:"cred_id" gorm:"type:uuid;primary_key;"`
	MicroserviceId string    `json:"microservice_id" gorm:"foreignKey:MicroserviceId"`
	RoleId         string    `json:"role_id" gorm:"foreignKey:RoleId"`
	DBName         string    `json:"db_name" gorm:"unique"`
	Type           string    `json:"type"`
	URL            string    `json:"url"  gorm:"unique"`
	Port           string    `json:"port"  gorm:"unique"`
	DBUsername     string    `json:"db_username" gorm:"unique"`
	DBPassword     string    `json:"db_password"`
	LastUsed       time.Time `json:"last_used"`
	LastUsedBy     string    `json:"last_used_by"  gorm:"foreignKey:Username"`
	Created        time.Time `json:"created"`
}

func (c *Cred) BeforeCreate(_ *gorm.DB) (err error) {
	c.CredId = uuid.New()
	c.Created = time.Now()
	return
}

//-----------------------------------------------------------------------------

type Microservice struct {
	MicroserviceId uuid.UUID `json:"microservice_id" gorm:"type:uuid;primary_key;"`
	Name           string    `json:"name" gorm:"unique"`
	RoleId         string    `json:"role_id" gorm:"foreignKey:RoleId"`
	Created        time.Time `json:"created"`
}

func (m *Microservice) BeforeCreate(_ *gorm.DB) (err error) {
	m.MicroserviceId = uuid.New()
	m.Created = time.Now()
	return
}

//-----------------------------------------------------------------------------

type APIPath struct {
	APIPathId      uuid.UUID `json:"api_path_id" gorm:"type:uuid;primary_key;"`
	MicroserviceId string    `json:"microservice_id" gorm:"foreignKey:MicroserviceId"`
	Path           string    `json:"path"`
}

func (a *APIPath) BeforeCreate(_ *gorm.DB) (err error) {
	a.APIPathId = uuid.New()
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

type UserRole struct {
	AdminId uuid.UUID `json:"admin_id" gorm:"foreignKey:AdminId"`
	RoleId  uuid.UUID `json:"role_id" gorm:"foreignKey:RoleId"`
	Created time.Time `json:"created"`
}

func (ur *UserRole) BeforeCreate(_ *gorm.DB) (err error) {
	ur.Created = time.Now()
	return
}

//-----------------------------------------------------------------------------

type Role struct {
	RoleId   uuid.UUID `json:"role_id" gorm:"type:uuid;primary_key;"`
	RoleName string    `json:"role_name"`
	Created  time.Time `json:"created"`
}

func (r *Role) BeforeCreate(_ *gorm.DB) (err error) {
	r.RoleId = uuid.New()
	r.Created = time.Now()
	return
}

//-----------------------------------------------------------------------------
