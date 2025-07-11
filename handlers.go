package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/cliveyg/poptape-admin/utils"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"net/http"
	"os"
	"slices"
	"time"
)

//-----------------------------------------------------------------------------

func (a *App) FetchCreds(c *gin.Context) {
	credId, err := uuid.Parse(c.Param("cId"))
	if err != nil {
		a.Log.Info().Msgf("Invalid cred id in url [%s]", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request"})
		return
	}
	cr := Cred{}
	res := a.DB.First(&cr, credId)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			a.Log.Info().Msgf("Cred [%s] not found", cr.CredId.String())
			c.JSON(http.StatusNotFound, gin.H{"message": "Creds not found"})
			return
		}
		a.Log.Info().Msgf("Error finding creds [%s]", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went neee"})
		return
	}
	cr.DBPassword = "XXXXX"
	c.JSON(http.StatusOK, gin.H{"creds": &cr})
}

//-----------------------------------------------------------------------------

func (a *App) CreateCreds(c *gin.Context) {
	var cr Cred
	var ms Microservice
	var rl Role
	err := c.ShouldBindBodyWith(&cr, binding.JSON)
	if err != nil {
		a.Log.Info().Msgf("Unable to bind to cred struct: [%s]", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request [1]"})
		return
	}
	err = c.ShouldBindBodyWith(&ms, binding.JSON)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request [2]"})
		a.Log.Info().Msgf("Unable to bind to microservice struct: [%s]", err.Error())
		return
	}
	err = c.ShouldBindBodyWith(&rl, binding.JSON)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request [3]"})
		a.Log.Info().Msgf("Unable to bind to role struct: [%s]", err.Error())
		return
	}

	err = a.encryptCredPass(&cr)
	if err != nil {
		a.Log.Info().Msgf("%s", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request [4]"})
		return
	}

	err = a.DB.Transaction(func(tx *gorm.DB) error {

		var i interface{}
		i, _ = c.Get("user")
		u := i.(User)
		cr.CreatedBy = u.AdminId
		ms.CreatedBy = u.AdminId

		if err = tx.Create(&cr).Error; err != nil {
			return err
		}
		if err = tx.FirstOrCreate(&ms, &ms).Error; err != nil {
			return err
		}
		crm := RoleCredMS{
			MicroserviceId: ms.MicroserviceId,
			RoleName:       rl.Name,
			CredId:         cr.CredId,
			CreatedBy:      u.AdminId,
		}
		if err = tx.Create(&crm).Error; err != nil {
			return err
		}

		// commit transaction
		return nil
	})
	if err != nil {
		a.Log.Info().Msgf("Unable to commit transaction to db [%s]", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went boom"})
		return
	}

	msg := fmt.Sprintf("Creds created; credId is [%s]", cr.CredId.String())
	c.JSON(http.StatusCreated, gin.H{"message": msg})

}

//-----------------------------------------------------------------------------

func (a *App) FetchAllUsers(c *gin.Context) {
	//TODO pagination
	var users []User
	res := a.DB.Preload("Roles").Find(&users)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"message": "No users not found"})
			a.Log.Error().Msg("Nothing in users table!")
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went pop"})
		a.Log.Error().Err(res.Error)
	}
	c.JSON(http.StatusOK, gin.H{"users": users})
}

//-----------------------------------------------------------------------------

func (a *App) FetchUser(c *gin.Context) {
	adminId, err := uuid.Parse(c.Param("aId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request"})
		a.Log.Info().Msgf("Not a uuid string: [%s]", err.Error())
		return
	}
	u := User{AdminId: adminId}
	res := a.DB.Preload("Roles").Find(&u)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
			a.Log.Info().Msgf("User [%s] not found", u.AdminId.String())
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went pop"})
		a.Log.Info().Msgf("Error finding user [%s]", err.Error())
		return
	}

	if u.Username == "" {
		c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"user": u})
}

//-----------------------------------------------------------------------------

func (a *App) AddRoleToUser(c *gin.Context) {

	adminId, err := uuid.Parse(c.Param("aId"))
	if err != nil {
		a.Log.Info().Msgf("Not a uuid string: [%s]", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request"})
		return
	}
	rName := c.Param("rName")
	if len(rName) > 20 {
		a.Log.Info().Msg("role name is too long")
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request"})
	}

	u := User{AdminId: adminId}
	res := a.DB.Preload("Roles").Find(&u)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
			a.Log.Info().Msgf("User [%s] not found", u.AdminId.String())
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went pop"})
		a.Log.Info().Msgf("Error finding user [%s]", err.Error())
		return
	}

	if u.Username == "" {
		c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
		return
	}

	rf := false
	rls := u.Roles
	for i := 0; i < len(rls); i++ {
		if rName == rls[i].Name {
			rf = true
			break
		}
	}

	if !rf {
		rl := Role{Name: rName}
		res = a.DB.First(&rl)
		if res.Error != nil {
			c.JSON(http.StatusNotFound, gin.H{"message": "Role does not exist"})
			return
		}
		u.Roles = append(rls, rl)
		res = a.DB.Save(&u)
		if res.Error != nil {
			a.Log.Info().Msgf("Failed to add role to user: [%s]", res.Error)
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went bang [3]"})
			return
		}
		ms := fmt.Sprintf("Role added to user [%s]", u.AdminId.String())
		c.JSON(http.StatusCreated, gin.H{"message": ms})
		return
	}

	c.JSON(http.StatusNotModified, nil)

}

//-----------------------------------------------------------------------------

func (a *App) DeleteUser(c *gin.Context) {
	a.Log.Debug().Msg("Deleting user")
	adminId, err := uuid.Parse(c.Param("aId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request"})
		a.Log.Info().Msgf("Not a uuid string: [%s]", err.Error())
		return
	}
	u := User{AdminId: adminId}
	res := a.DB.Delete(&u)
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went pop"})
		a.Log.Info().Msgf("Unable to delete user: [%s]", err.Error())
		return
	}
	a.Log.Info().Msgf("User [%s] deleted", u.AdminId.String())
	c.JSON(http.StatusGone, gin.H{"message": "User deleted"})
}

//-----------------------------------------------------------------------------

func (a *App) CreateUser(c *gin.Context) {
	var su Signup
	err := c.ShouldBindJSON(&su)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request [1]"})
		a.Log.Info().Msgf("Signup failed: [%s]", err.Error())
		return
	}
	if su.Password != su.ConfirmPassword {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Passwords don't match"})
		a.Log.Info().Msgf("Signup failed: [%s]", errors.New("passwords don't match"))
		return
	}
	// password is sent base64 encoded - so need to decode
	var pass []byte
	pass, err = base64.StdEncoding.DecodeString(su.Password)
	if err != nil {
		a.Log.Info().Msgf("Base64 decoding failed [%s]", err.Error())
		return
	}
	var epw []byte
	epw, err = utils.GenerateHashPassword(pass)
	u := User{Username: su.Username, Password: epw}
	u.Roles = append(u.Roles, Role{Name: "admin"})

	a.Log.Info().Interface("User: ", u).Send()

	res := a.DB.Create(&u)
	if res.Error != nil {
		a.Log.Info().Msgf("Signup failed: [%s]", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went bang [1]"})
		return
	}

	// validate user if in DEV env
	ms := fmt.Sprintf("User [%s] created but not validated; Id is [%s]", u.Username, u.AdminId.String())
	if os.Getenv("ENVIRONMENT") == "DEV" {
		u.Validated = true
		res = a.DB.Save(&u)
		if res.Error != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went bang [3]"})
			a.Log.Info().Msgf("Signup failed: [%s]; Unable to validate user [%s]", err.Error(), u.Username)
			return
		}
		ms = fmt.Sprintf("User [%s] created and validated; Id is [%s]", u.Username, u.AdminId.String())
	}

	c.Header("y-access-token", c.GetString("token"))
	c.JSON(http.StatusCreated, gin.H{"message": ms})
}

//-----------------------------------------------------------------------------

func (a *App) TestRoute(c *gin.Context) {
	a.Log.Debug().Msg("All valid and in TestRoute")
	c.Header("y-access-token", c.GetString("token"))
	c.JSON(http.StatusOK, gin.H{"message": "meeeep"})
}

//-----------------------------------------------------------------------------

func (a *App) Login(c *gin.Context) {
	var lg Login
	err := c.ShouldBindJSON(&lg)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request"})
		a.Log.Info().Msgf("Login failed: [%s]", err.Error())
		return
	}

	u := User{Username: lg.Username}
	if a.checkLoginDetails(&lg, &u) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Username or password incorrect"})
		return
	}

	a.Log.Debug().Msg("Login OK; Creating JWT")
	token, err := utils.GenerateToken(u.Username, u.AdminId)
	if err != nil {
		a.Log.Info().Msgf("Error creating JWT; Error [%s]", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went bang"})
		return
	}
	u.LastLogin = time.Now()
	res := a.DB.Save(&u)
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Ooops"})
		a.Log.Info().Msgf("Unable to update user last login: [%s]", err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": token})
}

//-----------------------------------------------------------------------------

func (a *App) BackupDB(c *gin.Context) {

	a.Log.Debug().Msg("In BackupDB")
	var msId uuid.UUID
	var err error
	dbName := ""
	tab := ""
	/*
		type Params struct {
			mode string `form:"mode"`
		}
		// by default we select all; which is both db schema and data
		var m Params
		if err := c.ShouldBind(&m); err != nil {
			a.Log.Info().Msgf("error fetching querystring [%s]", err.Error())
			c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request"})
			return
		}

	*/
	m := c.Query("mode")

	vl := []string{"schema", "all", "data"}
	//a.Log.Debug().Msgf("Mode is [%s]", m.mode)
	//if !slices.Contains(vl, m.mode) {
	a.Log.Debug().Msgf("Mode is [%s]", m)
	if !slices.Contains(vl, m) {
		a.Log.Info().Msg("Invalid mode value")
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request"})
		return
	}

	msId, err = uuid.Parse(c.Param("msId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request"})
		a.Log.Info().Msgf("Not a uuid string: [%s]", err.Error())
		return
	}

	dbName = c.Param("db")
	tab = c.Param("tab")

	a.Log.Debug().Msgf("Input vars are: msId [%s], db [%s], tab [%s], mode [%s]", msId.String(), dbName, tab, m)
	c.JSON(http.StatusTeapot, gin.H{"message": "Moop"})

}
