package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/cliveyg/poptape-admin/utils"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/gridfs"
	"gorm.io/gorm"
	"io"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strconv"
)

//-----------------------------------------------------------------------------

func (a *App) ListAllCreds(c *gin.Context) {
	var crds []Cred
	res := a.DB.Find(&crds)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			a.Log.Info().Msg("No creds found")
			c.JSON(http.StatusNotFound, gin.H{"message": "No creds found"})
			return
		}
		a.Log.Info().Msgf("Error returning creds [%s]", res.Error.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went nope"})
		return
	}
	for i := range crds {
		crds[i].DBPassword = "XXXX"
	}
	c.JSON(http.StatusOK, gin.H{"creds": crds})
}

//-----------------------------------------------------------------------------

func (a *App) FetchCredsById(c *gin.Context) {

	//credId, err := uuid.Parse(c.Param("cId"))
	if !utils.IsValidUUID(c.Param("cId")) {
		a.Log.Info().Msg("Invalid cred id in url")
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request"})
		return
	}
	credId := c.Param("cId")
	//if err != nil {
	//	a.Log.Info().Msgf("Invalid cred id in url [%s]", err.Error())
	//	c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request"})
	//	return
	//}
	cr := Cred{}
	res := a.DB.First(&cr, credId)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			a.Log.Info().Msgf("Cred [%s] not found", cr.CredId.String())
			c.JSON(http.StatusNotFound, gin.H{"message": "Creds not found"})
			return
		}
		a.Log.Info().Msgf("Error finding creds [%s]", res.Error.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went neee"})
		return
	}

	cr.DBPassword = "XXXXX"
	c.JSON(http.StatusOK, gin.H{"creds": &cr})
}

//-----------------------------------------------------------------------------

func (a *App) CreateCreds(c *gin.Context) {

	var cr Cred
	var msi MsIn
	var ms Microservice
	var rl Role
	var err error
	if err = c.ShouldBindBodyWith(&cr, binding.JSON); err != nil {
		a.Log.Info().Msgf("Unable to bind to cred struct: [%s]", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request [1]"})
		return
	}
	if cr.Type != "postgres" && cr.Type != "mongo" {
		a.Log.Info().Msgf("Incorrect db type")
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request; Incorrect db type"})
		return
	}
	if err = c.ShouldBindBodyWith(&msi, binding.JSON); err != nil {
		a.Log.Info().Msgf("Unable to bind to microservice struct: [%s]", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request [2]"})
		return
	}
	err = c.ShouldBindBodyWith(&rl, binding.JSON)
	if err = c.ShouldBindBodyWith(&rl, binding.JSON); err != nil {
		a.Log.Info().Msgf("Unable to bind to role struct: [%s]", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request [3]"})
		return
	}

	if err = a.encryptCredPass(&cr); err != nil {
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
		ms.MSName = msi.MSName

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
	// TODO pagination? - not sure it needs it tbh
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

	var u User
	var rName string
	if err := a.getRoleDetails(c, &u, &rName); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request"})
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
		res := a.DB.First(&rl)
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
		ms := fmt.Sprintf("Role [%s] added to user [%s]", rName, u.AdminId.String())
		c.JSON(http.StatusCreated, gin.H{"message": ms})
		return
	}

	c.JSON(http.StatusNotModified, nil)

}

//-----------------------------------------------------------------------------

func (a *App) RemoveRoleFromUser(c *gin.Context) {

	var u User
	var rName string
	if err := a.getRoleDetails(c, &u, &rName); err != nil {
		a.Log.Info().Msgf("Error is [%s]", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request"})
		return
	}

	rf := false
	rls := u.Roles
	var ix int

	for i := 0; i < len(rls); i++ {
		if rName == rls[i].Name {
			rf = true
			ix = i
			break
		}
	}

	if rf {
		rl := Role{Name: rName}
		res := a.DB.First(&rl)
		if res.Error != nil {
			c.JSON(http.StatusNotFound, gin.H{"message": "Role does not exist"})
			return
		}
		nrls := append(u.Roles[:ix], u.Roles[ix+1:]...)
		a.Log.Info().Interface("u.Roles", u.Roles).Send()
		a.Log.Info().Interface("nrls", nrls).Send()

		err := a.DB.Model(&u).Association("Roles").Clear()
		if err != nil {
			a.Log.Info().Msgf("Failed to clear role association from user: [%s]", res.Error)
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went bang [3]"})
			return
		}
		u.Roles = nrls

		res = a.DB.Save(&u)
		if res.Error != nil {
			a.Log.Info().Msgf("Failed to delete role from user: [%s]", res.Error)
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went bang [4]"})
			return
		}
		ms := fmt.Sprintf("Role [%s] removed from user [%s]", rName, u.AdminId.String())
		c.JSON(http.StatusGone, gin.H{"message": ms})
		return
	}

	c.JSON(http.StatusNotModified, gin.H{"message": "Incorrect input"})

}

//-----------------------------------------------------------------------------

func (a *App) EditUser(c *gin.Context) {

	a.Log.Debug().Msg("Editing user")
	adminId, err := uuid.Parse(c.Param("aId"))
	if err != nil {
		a.Log.Info().Msgf("Not a uuid string: [%s]", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request"})
		return
	}

	// get the user from request body
	var ufb User
	if err = c.ShouldBindJSON(&ufb); err != nil {
		a.Log.Info().Msgf("Unable to bind input to struc", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request"})
		return
	}

	if adminId != ufb.AdminId {
		a.Log.Info().Msgf("Admin Id's don't match", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request"})
		return
	}

	// get the user from request url admin id
	ufu := User{AdminId: adminId}
	res := a.DB.Preload("Roles").Find(&ufu)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			a.Log.Info().Msgf("User [%s] not found", ufu.AdminId.String())
			c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
			return
		}
		a.Log.Info().Msgf("Error finding user [%s]", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went pop"})
		return
	}

	if ufu.Username == "" {
		c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
		return
	}

	res = a.DB.Save(&ufu)
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went bang [4]"})
		a.Log.Info().Msgf("Unable to edit user [%s] because of error: [%s]", ufu.Username, err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "User details successfully changed"})
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
	var err error
	if err = c.ShouldBindJSON(&su); err != nil {
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
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad base64 encoding"})
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
	c.JSON(http.StatusOK, gin.H{"message": "meeeep!"})
}

//-----------------------------------------------------------------------------

func (a *App) Login(c *gin.Context) {
	var lg Login
	var err error
	if err = c.ShouldBindJSON(&lg); err != nil {
		a.Log.Info().Msgf("Login failed: [%s]", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request"})
		return
	}

	u := User{Username: lg.Username}
	if a.checkLoginDetails(&lg, &u) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Username and/or password incorrect"})
		return
	}

	a.Log.Debug().Msg("Login OK; Creating JWT")
	token, err := utils.GenerateToken(u.Username, u.AdminId)
	if err != nil {
		a.Log.Info().Msgf("Error creating JWT; Error [%s]", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went bang"})
		return
	}
	a.Log.Debug().Interface("User", u).Send()
	c.Set("user", u)
	res := a.DB.Set("login", true).Set("user", u).Save(&u)

	if res.Error != nil {
		a.Log.Info().Msgf("Unable to update user last login: [%s]", res.Error)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Ooops"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": token})
}

//-----------------------------------------------------------------------------

func (a *App) Testy(c *gin.Context) {
	a.Log.Debug().Msg("In Testy")
	c.JSON(http.StatusTeapot, gin.H{"message": "Cup of tea?"})
}

//-----------------------------------------------------------------------------

func (a *App) BackupDB(c *gin.Context) {

	a.Log.Debug().Msg("In BackupDB")

	saveId := uuid.New()
	var msId uuid.UUID
	var err error
	var statusCode int
	var creds Cred
	var u User
	dbName := ""
	tabColl := ""
	mode := ""

	statusCode, err = a.prepSaveRestore(c, &dbName, &tabColl, &mode, &creds, &u, &msId)
	if err != nil {
		c.JSON(statusCode, gin.H{"message": err.Error()})
		return
	}

	if creds.Type == "postgres" {
		if err := a.backupPostgres(&creds, &msId, &u, dbName, tabColl, mode, &saveId); err != nil {
			a.Log.Info().Msgf("Error backing up db [%s]", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went pop when backing up"})
			return
		}
		var m string
		if tabColl != "" {
			m = fmt.Sprintf("Table [%s] from [%s] db saved", tabColl, dbName)
		} else {
			m = fmt.Sprintf("[%s] db saved", dbName)
		}
		c.JSON(http.StatusCreated, gin.H{"message": m, "save_id": saveId.String()})
		return
	}
	if creds.Type == "mongo" {
		c.JSON(http.StatusTeapot, gin.H{"message": "Mongie!"})
		return
	}

	c.JSON(http.StatusUnprocessableEntity, gin.H{"message": "Something's not right"})

}

//-----------------------------------------------------------------------------

func (a *App) RestoreDB(c *gin.Context) {

	a.Log.Debug().Msg("In RestoreDB")
	var msId uuid.UUID
	var err error
	var statusCode int
	var creds Cred
	var u User
	dbName := ""
	tabColl := ""
	mode := ""

	statusCode, err = a.prepSaveRestore(c, &dbName, &tabColl, &mode, &creds, &u, &msId)
	if err != nil {
		c.JSON(statusCode, gin.H{"message": err.Error()})
		return
	}

	a.Log.Debug().Msgf("Input vars are: msId [%s], db [%s], tab [%s], mode [%s]", msId.String(), dbName, tabColl, mode)
	c.JSON(http.StatusTeapot, gin.H{"message": "Moop"})

}

//-----------------------------------------------------------------------------

//goland:noinspection GoErrorStringFormat
func (a *App) prepSaveRestore(c *gin.Context, dbName, tabColl, mode *string, creds *Cred, u *User, msId *uuid.UUID) (int, error) {

	*mode = c.Query("mode")

	vl := []string{"schema", "all", "data"}
	if !slices.Contains(vl, *mode) {
		a.Log.Info().Msg("Invalid mode value")
		return http.StatusBadRequest, errors.New("Invalid mode value")
	}

	if err := utils.ValidDataInput(c.Param("db")); err != nil {
		a.Log.Info().Msg("Invalid data input for db param")
		return http.StatusBadRequest, errors.New("Invalid data input for db param")
	}

	if err := utils.ValidDataInput(c.Param("tab")); err != nil {
		a.Log.Info().Msg("Invalid data input for table/collection param")
		return http.StatusBadRequest, errors.New("Invalid data input for table/collection param")
	}
	*dbName = c.Param("db")
	*tabColl = c.Param("tab")

	// we should already have the msId and credId from the auth/access middleware
	var credId uuid.UUID
	if err := a.getUUIDFromParams(c, &credId, "cred_id"); err != nil {
		a.Log.Info().Msgf("Error getting uuid from params [%s]", err.Error())
		return http.StatusBadRequest, errors.New("Error getting uuid from cred param")
	}
	if err := a.getUUIDFromParams(c, msId, "ms_id"); err != nil {
		a.Log.Info().Msgf("Error getting uuid from params [%s]", err.Error())
		return http.StatusBadRequest, errors.New("Error getting uuid from ms param")
	}

	a.Log.Debug().Msgf("Input vars are: credId [%s], db [%s], tabColl [%s], mode [%s]", credId.String(), *dbName, *tabColl, *mode)

	creds.CredId = credId
	res := a.DB.First(&creds, credId)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			a.Log.Info().Msgf("Creds [%s] not found", credId.String())
			return http.StatusNotFound, errors.New("Creds not found")
		}
		a.Log.Info().Msgf("Error finding creds [%s]", res.Error.Error())
		return http.StatusInternalServerError, errors.New("Something went pop")
	}

	if *dbName != creds.DBName {
		a.Log.Info().Msgf("DB name [%s] is incorrect", dbName)
		return http.StatusNotFound, errors.New("DB name is invalid")
	}

	var i interface{}
	i, _ = c.Get("user")
	*u = i.(User)
	// as getting consumes the resource we have to reset it
	c.Set("user", u)

	return http.StatusOK, nil
}

func (a *App) ListMicroservices(c *gin.Context) {

	var mss []Microservice
	var u User
	if value, exists := c.Get("user"); exists {
		u = value.(User)
	}
	a.Log.Info().Interface("User", u).Send()
	if a.userHasValidRole(u.Roles, []string{"super", "admin"}) {
		a.Log.Debug().Msg("User has a valid role")
	}

	res := a.DB.Order("ms_name asc").Find(&mss)
	if res.Error != nil || len(mss) == 0 {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) || len(mss) == 0 {
			c.JSON(http.StatusNotFound, gin.H{"message": "No microservices found"})
			return
		}
		a.Log.Info().Msgf("Error finding microservices [%s]", res.Error)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went neee"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"microservices": mss})

}

//-----------------------------------------------------------------------------

func (a *App) ListAllRoles(c *gin.Context) {
	var roles []Role
	var u User
	if value, exists := c.Get("user"); exists {
		u = value.(User)
	}
	a.Log.Info().Interface("User", u).Send()
	if a.userHasValidRole(u.Roles, []string{"super", "admin"}) {
		a.Log.Debug().Msg("User has a valid role")
	}

	res := a.DB.Find(&roles)
	if res.Error != nil || len(roles) == 0 {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			a.Log.Info().Msg("Microservice table is empty!")
			c.JSON(http.StatusNotFound, gin.H{"message": "No microservices found"})
			return
		}
		a.Log.Info().Msgf("Error finding microservices [%s]", res.Error)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went neee"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"roles": roles})
}

//-----------------------------------------------------------------------------

func (a *App) ListAllSavesByMicroservice(c *gin.Context) {

	// TODO: Pagination?

	var msId uuid.UUID
	if err := a.getUUIDFromParams(c, &msId, "ms_id"); err != nil {
		a.Log.Info().Msgf("Error getting uuid from params [%s]", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"message": "Microservice id is invalid"})
	}

	var saves []SaveRecord
	var res *gorm.DB
	// look for querystring valid= if not there then return all valid
	// and invalid records
	validStr := c.Query("valid")
	if validStr != "" {
		vl := []string{"true", "false"}
		if !slices.Contains(vl, validStr) {
			a.Log.Info().Msg("Value of 'valid' querystring is invalid")
			c.JSON(http.StatusBadRequest, gin.H{"message": "Value of 'valid' querystring is invalid"})
			return
		}
		v, _ := strconv.ParseBool(validStr)
		res = a.DB.Where(map[string]interface{}{"microservice_id": msId.String(), "valid": v}).Order("created desc").Find(&saves)
	} else {
		res = a.DB.Where("microservice_id = ?", msId.String()).Order("created desc").Find(&saves)
	}
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			a.Log.Info().Msg("No saves found")
			c.JSON(http.StatusNotFound, gin.H{"message": "No saves found"})
			return
		}
		a.Log.Info().Msgf("Error returning saves [%s]", res.Error.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went nope"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"saves": saves})
}

//-----------------------------------------------------------------------------

func (a *App) RestoreDBBySaveId(c *gin.Context) {

	if !utils.IsValidUUID(c.Param("saveId")) {
		a.Log.Info().Msg("Invalid saveId in url")
		c.JSON(http.StatusBadRequest, gin.H{"message": "Not a uuid string"})
		return
	}
	saveId, _ := uuid.Parse(c.Param("saveId"))
	svRec := SaveRecord{
		SaveId: saveId,
	}
	res := a.DB.First(&svRec)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			a.Log.Info().Msgf("Record not found for save id [%s]", saveId)
			c.JSON(http.StatusNotFound, gin.H{"message": "RoleCredMS record not found"})
			return
		}
		a.Log.Info().Msgf("Error finding SaveRecord [%s]", res.Error.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went whump"})
		return
	}
	a.Log.Debug().Msg("Found SaveRecord ✓")

	var i interface{}
	i, _ = c.Get("user")
	u := i.(User)
	c.Set("user", u)

	sc, err := a.userHasCorrectAccess(&svRec, &u)
	if err != nil {
		c.JSON(sc, gin.H{"message": err.Error()})
		return
	}

	a.Log.Debug().Msgf("User [%s] has correct access ✓", u.Username)

	db := a.Mongo.Database(svRec.DBName)
	collection := db.Collection("fs.files")
	var fileDoc bson.M
	ctx := c.Request.Context()
	err = collection.FindOne(ctx, bson.M{"metadata.save_id": svRec.SaveId.String()}).Decode(&fileDoc)
	if err != nil {
		a.Log.Info().Msgf("File not found for save_id %s: %s", svRec.SaveId.String(), err)
		c.JSON(http.StatusNotFound, gin.H{"message": "File not found for save id in mongo"})
		return
	}
	a.Log.Debug().Msg("Found document in mongo ✓")
	fileID, ok := fileDoc["_id"].(primitive.ObjectID)
	if !ok {
		a.Log.Info().Msgf("File _id is not ObjectID (got %T)", fileDoc["_id"])
		c.JSON(http.StatusUnprocessableEntity, gin.H{"message": "File _id is not ObjectID"})
		return
	}

	var bucket *gridfs.Bucket
	bucket, err = gridfs.NewBucket(db)
	if err != nil {
		a.Log.Info().Msgf("gridfs.NewBucket error: %s", err)
		c.JSON(http.StatusUnprocessableEntity, gin.H{"message": "gridfs.NewBucket error"})
		return
	}
	a.Log.Debug().Msg("Created bucket ✓")

	downloadStream, err := bucket.OpenDownloadStream(fileID)
	if err != nil {
		a.Log.Info().Msgf("OpenDownloadStream error: %s", err)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "OpenDownloadStream error"})
		return
	}
	defer downloadStream.Close()
	a.Log.Debug().Msg("OpenDownloadStream success ✓")

	var stdoutBuf, stderrBuf bytes.Buffer

	crdRec := Cred{
		CredId: svRec.CredId,
	}

	res = a.DB.First(&crdRec)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			a.Log.Info().Msgf("Record not found for cred id [%s]", crdRec.CredId.String())
			c.JSON(http.StatusNotFound, gin.H{"message": "Cred record not found"})
			return
		}
		a.Log.Info().Msgf("Error finding Cred [%s]", res.Error.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went whump"})
		return
	}
	key := []byte(os.Getenv("SUPERSECRETKEY"))
	nonce := []byte(os.Getenv("SUPERSECRETNONCE"))
	var pw []byte
	pw, err = utils.Decrypt(crdRec.DBPassword, key, nonce)
	if err != nil {
		a.Log.Info().Msgf("Error decrypting password from creds [%s]", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went plop"})
		return
	}

	if svRec.Mode == "schema" || svRec.Mode == "all" {
		if svRec.Table != "" {
			dc := fmt.Sprintf("DROP TABLE %s", svRec.Table)
			_, err = a.writeSQLOut(dc, &crdRec, &pw, false)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went plink"})
				return
			} else {
				a.Log.Debug().Msgf("Successfully dropped table [%s] ✓", svRec.Table)
			}
		} else {
			// all tables
			var tabs []string
			tabs, err = a.listTables(&crdRec, &pw)
			if err != nil {
				a.Log.Info().Msgf("Error listing tables [%s]", res.Error.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went scree"})
				return
			}
			for _, table := range tabs {
				// index is the index where we are
				// element is the element from someSlice for where we are
				a.Log.Debug().Msgf("Table is [%s]", table)
				dc := fmt.Sprintf("DROP TABLE %s", table)
				_, err = a.writeSQLOut(dc, &crdRec, &pw, false)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went plink"})
					return
				} else {
					a.Log.Debug().Msgf("Successfully dropped table [%s] ✓", svRec.Table)
				}
			}

		}

	} else if svRec.Mode == "data" {
		// remove all existing records from 1 table
		if svRec.Table != "" {
			dc := fmt.Sprintf("DELETE FROM %s;", svRec.Table)
			_, err = a.writeSQLOut(dc, &crdRec, &pw, false)
			if err != nil {
				//a.Log.Info().Msgf("Error writing sql out [%s]", res.Error.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went plink"})
				return
			} else {
				a.Log.Debug().Msgf("Successfully deleted data from table [%s] ✓", svRec.Table)
			}
		} else {
			// remove all recs from all tables
			var tabs []string
			tabs, err = a.listTables(&crdRec, &pw)
			if err != nil {
				a.Log.Info().Msgf("Error listing tables [%s]", res.Error.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went scree"})
				return
			}
			errFound := false
			for _, table := range tabs {
				// TODO: put in one transaction
				a.Log.Debug().Msgf("Table is [%s]", table)
				dc := fmt.Sprintf("DELETE FROM %s;", table)
				_, err = a.writeSQLOut(dc, &crdRec, &pw, false)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went plink"})
					return
				} else {
					a.Log.Debug().Msgf("Successfully deleted from tables [%s] ✓", table)
				}
			}
			if errFound {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went kerching"})
				return
			}
		}

	}

	// build psql arguments
	args := []string{
		"-h", crdRec.Host,
		"-U", crdRec.DBUsername,
		"-p", crdRec.DBPort,
		"-d", crdRec.DBName,
		"-f", "-",
		"-v", "ON_ERROR_STOP=1",
	}
	a.Log.Debug().Msgf("args is <<%s>>", args)
	cmd := exec.Command("psql", args...)
	cmd.Env = append(os.Environ(), "PGPASSWORD="+string(pw))
	a.Log.Debug().Msg("After exec.Command ✓")

	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	var stdin io.WriteCloser
	stdin, err = cmd.StdinPipe()
	if err != nil {
		a.Log.Info().Msgf("WriteCloser error [%s]", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went ping"})
		return
	}
	defer stdin.Close()
	a.Log.Debug().Msg("After defer stdin.Close ✓")

	if err = cmd.Start(); err != nil {
		a.Log.Info().Msgf("cmd.Start error [%s]", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went twang"})
		return
	}
	a.Log.Debug().Msg("After cmd.Start ✓")

	_, err = io.Copy(stdin, downloadStream)
	if err != nil {
		a.Log.Info().Msgf("io.Copy error [%s]", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went splash"})
		return
	}
	stdin.Close()
	a.Log.Debug().Msg("After stdin.Close ✓")

	if err = cmd.Wait(); err != nil {
		a.Log.Debug().Msgf("psql failed: %s\nstderr: %s\nstdout: %s", err.Error(), stderrBuf.String(), stdoutBuf.String())
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "psql failed",
			"stderr":  stderrBuf.String(),
			"stdout":  stdoutBuf.String(),
		})
		return
	}

	c.JSON(http.StatusTeapot, gin.H{
		"message":  "psql",
		"stderr":   stderrBuf.String(),
		"stdout":   stdoutBuf.String(),
		"save_rec": svRec,
	})
}

//-----------------------------------------------------------------------------

func (a *App) ListAllSaves(c *gin.Context) {

	var allSaves []SaveRecord
	res := a.DB.Find(&allSaves)
	if res.Error != nil || len(allSaves) == 0 {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			a.Log.Info().Msg("SaveRecord table is empty!")
			c.JSON(http.StatusNotFound, gin.H{"message": "No save records found"})
			return
		}
		a.Log.Info().Msgf("Error finding SaveRecord table [%s]", res.Error)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went neee"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"total_saves": len(allSaves), "saves": allSaves})

	//c.JSON(http.StatusLocked, gin.H{"message": "Danger! Will Smith; Danger!"})

}

//-----------------------------------------------------------------------------

func (a *App) RestoreSystemByDataSet(c *gin.Context) {
	c.JSON(http.StatusLocked, gin.H{"message": "Danger! Will Smith; Danger!"})
}

//-----------------------------------------------------------------------------

func (a *App) SystemWipe(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "wibble"})
}

//-----------------------------------------------------------------------------

