package main

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
	"time"
)

type User struct {
	AdminId   string    `json:"admin_id" gorm:"type:uuid;primary_key;"`
	Username  string    `json:"username" gorm:"unique"`
	Password  string    `json:"password"`
	LastLogin time.Time `json:"last_login"`
	Active    bool      `json:"active"`
	Validated bool      `json:"validated"`
	Created   time.Time `json:"created"`
}

func (u *User) BeforeCreate(_ *gorm.DB) (err error) {
	u.AdminId = uuid.New().String()
	return
}

type Cred struct {
	CredId         string    `json:"cred_id" gorm:"type:uuid;primary_key;"`
	MicroserviceId string    `json:"microservice_id" gorm:"foreignKey:MicroserviceId"`
	RoleId         string    `json:"role_id" gorm:"foreignKey:RoleId"`
	DBName         string    `json:"db_name" gorm:"unique"`
	Type           string    `json:"type"`
	IP             string    `json:"ip"  gorm:"unique"`
	Port           string    `json:"port"  gorm:"unique"`
	Username       string    `json:"username" gorm:"unique"`
	Password       string    `json:"password"`
	LastUsed       time.Time `json:"last_used"`
	LastUsedBy     string    `json:"last_used_by"`
	Created        time.Time `json:"created"`
}

func (c *Cred) BeforeCreate(_ *gorm.DB) (err error) {
	c.CredId = uuid.New().String()
	return
}

type Microservice struct {
	MicroserviceId string    `json:"microservice_id" gorm:"type:uuid;primary_key;"`
	Name           string    `json:"name" gorm:"unique"`
	RoleId         string    `json:"role_id" gorm:"foreignKey:RoleId"`
	Created        time.Time `json:"created"`
}

func (m *Microservice) BeforeCreate(_ *gorm.DB) (err error) {
	m.MicroserviceId = uuid.New().String()
	return
}

type APIPath struct {
	APIPathId      string `json:"api_path_id" gorm:"type:uuid;primary_key;"`
	MicroserviceId string `json:"microservice_id" gorm:"foreignKey:MicroserviceId"`
	Path           string `json:"path"`
}

func (a *APIPath) BeforeCreate(_ *gorm.DB) (err error) {
	a.APIPathId = uuid.New().String()
	return
}

type Login struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Signup struct {
	Username        string `json:"username"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
}

type UserRole struct {
	AdminId string    `json:"admin_id" gorm:"foreignKey:AdminId"`
	RoleId  string    `json:"role_id" gorm:"foreignKey:RoleId"`
	Created time.Time `json:"created"`
}

type Role struct {
	RoleId   string    `json:"role_id" gorm:"type:uuid;primary_key;"`
	RoleName string    `json:"role_name"`
	Created  time.Time `json:"created"`
}

func (r *Role) BeforeCreate(_ *gorm.DB) (err error) {
	r.RoleId = uuid.New().String()
	return
}
