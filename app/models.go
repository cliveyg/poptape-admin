package app

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
	Host       string    `json:"host" binding:"required"`
	Type       string    `json:"type" binding:"required"`
	URL        string    `json:"url" gorm:"unique" binding:"required"`
	DBPort     string    `json:"db_port" binding:"required"`
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
// TODO: Refactor the whole role/cred/microservice models thing. not sure they need
// TODO: to be separate

type RoleCredMS struct {
	MicroserviceId uuid.UUID `json:"microservice_id" gorm:"type:uuid"`
	CredId         uuid.UUID `json:"cred_id" gorm:"type:uuid"`
	RoleName       string    `json:"role_name" gorm:"foreignKey:Name"`
	CreatedBy      uuid.UUID `json:"created_by" gorm:"type:uuid"`
	Created        time.Time `json:"created"`
}

func (rcm *RoleCredMS) BeforeCreate(_ *gorm.DB) (err error) {
	rcm.Created = time.Now()
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
	Name    string    `json:"role_name" gorm:"type:string;primaryKey"`
	Created time.Time `json:"-"`
}

func (r *Role) BeforeCreate(_ *gorm.DB) (err error) {
	r.Created = time.Now()
	return
}

//-----------------------------------------------------------------------------

type SaveRecord struct {
	SaveId         uuid.UUID `json:"save_id" gorm:"type:uuid;primaryKey;"`
	MicroserviceId uuid.UUID `json:"microservice_id" gorm:"type:uuid" binding:"required"`
	CredId         uuid.UUID `json:"cred_id" gorm:"type:uuid" binding:"required"`
	DBName         string    `json:"db_name" binding:"required"`
	Table          string    `json:"table"`
	SavedBy        string    `json:"savedBy" binding:"required"`
	Version        int       `json:"version" binding:"required"`
	Dataset        int       `json:"dataset"`
	Mode           string    `json:"mode" binding:"required"`
	Valid          bool      `json:"valid" binding:"required"`
	Type           string    `json:"type" binding:"required"`
	Size           int64     `json:"size"`
	Notes          string    `json:"notes"`
	Created        time.Time `json:"created"`
	Updated        time.Time `json:"updated"`
}

func (s *SaveRecord) BeforeCreate(_ *gorm.DB) (err error) {
	s.Created = time.Now()
	s.Updated = time.Now()
	return
}

func (s *SaveRecord) BeforeUpdate(_ *gorm.DB) (err error) {
	s.Updated = time.Now()
	return
}

//-----------------------------------------------------------------------------

type Metadata struct {
	MicroserviceId uuid.UUID `json:"microservice_id"`
	CredId         uuid.UUID `json:"cred_id"`
	RoleName       string    `json:"role_name"`
	DBName         string    `json:"db_name"`
	Type           string    `json:"type"`
	LatestVersion  int       `json:"latest_version"`
	LastSaveId     uuid.UUID `json:"last_save_id"`
	SavedCount     int       `json:"saved_count"`
	ValidCount     int       `json:"valid_count"`
	InvalidCount   int       `json:"invalid_count"`
}
