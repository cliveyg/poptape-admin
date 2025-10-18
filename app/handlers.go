package app

import (
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
	"net/http"
	"os"
	"slices"
	"strconv"
)

//-----------------------------------------------------------------------------
// ListAllCreds
//-----------------------------------------------------------------------------

func (a *App) ListAllCreds(c *gin.Context) {
	var crds []Cred
	res := a.DB.Find(&crds)
	if res.Error != nil {
		a.Log.Info().Msgf("Error returning creds [%s]", res.Error.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went nope"})
		return
	}
	if len(crds) == 0 {
		a.Log.Info().Msg("No creds found")
		c.JSON(http.StatusNotFound, gin.H{"message": "No creds found"})
		return
	}
	for i := range crds {
		crds[i].DBPassword = "XXXX"
	}
	c.JSON(http.StatusOK, gin.H{"creds": crds})
}

//-----------------------------------------------------------------------------
// FetchCredsById
//-----------------------------------------------------------------------------

func (a *App) FetchCredsById(c *gin.Context) {

	if !utils.IsValidUUIDString(c.Param("cId")) {
		a.Log.Info().Msg("Invalid cred id in url")
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request"})
		return
	}
	credId, _ := uuid.Parse(c.Param("cId"))

	cr := Cred{CredId: credId}
	res := a.DB.First(&cr)
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
// CreateCreds
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

	if err = EncryptCredPass(&cr); err != nil {
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
// FetchAllUsers
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
		return
	}
	c.JSON(http.StatusOK, gin.H{"users": users})
}

//-----------------------------------------------------------------------------
// FetchUser
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
// AddRoleToUser
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
// RemoveRoleFromUser
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
// EditUser
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
		a.Log.Info().Msgf("Unable to bind input to struc [%s]", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request"})
		return
	}

	if adminId != ufb.AdminId {
		a.Log.Info().Msgf("Admin Id's don't match [%s]", err.Error())
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
// DeleteUser
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
// CreateUser
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

	a.Log.Debug().Interface("User: ", u).Send()

	res := a.DB.Create(&u)
	if res.Error != nil {
		a.Log.Info().Msgf("Signup failed: [%s]", res.Error.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went bang [1]"})
		return
	}

	// auto validate user if in DEV
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
// Login
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
	//a.Log.Debug().Interface("User", u).Send()
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
// BackupDB
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

	var n int64
	if creds.Type == "postgres" {
		if err = a.backupPostgres(&creds, &msId, &u, dbName, tabColl, mode, &saveId, &n); err != nil {
			a.Log.Info().Msgf("Error backing up db [%s]", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went pop when backing up Postgres"})
			return
		}
		var m string
		if tabColl != "" {
			m = fmt.Sprintf("Table [%s] from [%s] postgres db saved", tabColl, dbName)
		} else {
			m = fmt.Sprintf("[%s] postgres db saved", dbName)
		}
		c.JSON(http.StatusCreated, gin.H{"message": m, "no_of_bytes": n, "save_id": saveId.String()})
		return
	}
	if creds.Type == "mongo" {
		if err := a.backupMongo(&creds, &msId, &u, dbName, tabColl, mode, &saveId, &n); err != nil {
			a.Log.Info().Msgf("Error backing up MongoDB [%s]", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went pop when backing up MongoDB"})
			return
		}
		var m string
		if tabColl != "" {
			m = fmt.Sprintf("Collection [%s] from [%s] db saved", tabColl, dbName)
		} else {
			m = fmt.Sprintf("[%s] mongo db saved", dbName)
		}
		c.JSON(http.StatusCreated, gin.H{"message": m, "no_of_bytes": n, "save_id": saveId.String()})
		return
	}

	c.JSON(http.StatusUnprocessableEntity, gin.H{"message": "Something's not right"})

}

//-----------------------------------------------------------------------------
// RestoreDB
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
// prepSaveRestore
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
	if err := a.GetUUIDFromParams(c, &credId, "cred_id"); err != nil {
		a.Log.Info().Msgf("Error getting uuid from params [%s]", err.Error())
		return http.StatusBadRequest, errors.New("Error getting uuid from cred param")
	}
	if err := a.GetUUIDFromParams(c, msId, "ms_id"); err != nil {
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
		a.Log.Info().Msgf("DB name [%v] is incorrect", dbName)
		return http.StatusNotFound, errors.New("DB name is invalid")
	}

	var i interface{}
	i, _ = c.Get("user")
	*u = i.(User)
	// as getting consumes the resource we have to reset it
	c.Set("user", u)

	return http.StatusOK, nil
}

//-----------------------------------------------------------------------------
// ListMicroservices
//-----------------------------------------------------------------------------

func (a *App) ListMicroservices(c *gin.Context) {

	var mss []Microservice
	var u User
	if value, exists := c.Get("user"); exists {
		u = value.(User)
	}
	a.Log.Info().Interface("User", u).Send()
	if a.UserHasValidRole(u.Roles, []string{"super", "admin"}) {
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
// ListAllRoles
//-----------------------------------------------------------------------------

func (a *App) ListAllRoles(c *gin.Context) {
	var roles []Role
	var u User
	if value, exists := c.Get("user"); exists {
		u = value.(User)
	}
	a.Log.Info().Interface("User", u).Send()
	if a.UserHasValidRole(u.Roles, []string{"super", "admin"}) {
		a.Log.Debug().Msg("User has a valid role")
	}

	res := a.DB.Find(&roles)
	if res.Error != nil || len(roles) == 0 {
		a.Log.Info().Msgf("Error finding roles [%s]", res.Error)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went neee"})
		return
	}
	if len(roles) == 0 {
		a.Log.Info().Msg("Roles table is empty!")
		c.JSON(http.StatusNotFound, gin.H{"message": "No roles found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"roles": roles})
}

//-----------------------------------------------------------------------------
// ListAllSavesByMicroservice
//-----------------------------------------------------------------------------

func (a *App) ListAllSavesByMicroservice(c *gin.Context) {
	// TODO: Pagination?

	var msId uuid.UUID
	// can ignore possible errors as this gets checked in middleware too
	_ = a.GetUUIDFromParams(c, &msId, "ms_id")

	var saves []SaveRecord
	var res *gorm.DB // <- Use *gorm.DB, not DBInterface

	// look for querystring valid= if not there then return all valid and invalid records
	validStr := c.Query("valid")
	if validStr != "" {
		vl := []string{"true", "false"}
		if !slices.Contains(vl, validStr) {
			a.Log.Info().Msg("Value of 'valid' querystring is invalid")
			c.JSON(http.StatusBadRequest, gin.H{"message": "Value of 'valid' querystring is invalid"})
			return
		}
		v, _ := strconv.ParseBool(validStr)
		res = a.DB.Where(map[string]interface{}{"microservice_id": msId.String(), "valid": v}).
			Order("created desc").
			Find(&saves)
	} else {
		res = a.DB.Where("microservice_id = ?", msId.String()).
			Order("created desc").
			Find(&saves)
	}
	if res.Error != nil {
		a.Log.Info().Msgf("Error returning saves [%s]", res.Error.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went nope"})
		return
	}
	ls := len(saves)
	if ls == 0 {
		a.Log.Info().Msg("No saves found")
		c.JSON(http.StatusNotFound, gin.H{"message": "No saves found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"no_of_saves": ls, "saves": saves})
}

//-----------------------------------------------------------------------------
// RestoreDBBySaveId
//-----------------------------------------------------------------------------

func (a *App) RestoreDBBySaveId(c *gin.Context) {
	if !utils.IsValidUUIDString(c.Param("saveId")) {
		a.Log.Info().Msg("Invalid saveId in url")
		c.JSON(http.StatusBadRequest, gin.H{"message": "Not a uuid string"})
		return
	}
	saveId, _ := uuid.Parse(c.Param("saveId"))
	svRec := SaveRecord{SaveId: saveId}
	res := a.DB.First(&svRec)
	if res.Error != nil {
		status := http.StatusInternalServerError
		msg := "Something went whump"
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			a.Log.Info().Msgf("Record not found for save id [%s]", saveId)
			status = http.StatusNotFound
			msg = "RoleCredMS record not found"
		} else {
			a.Log.Info().Msgf("Error finding SaveRecord [%s]", res.Error.Error())
		}
		c.JSON(status, gin.H{"message": msg})
		return
	}
	a.Log.Debug().Msg("Found SaveRecord ✓")

	user, _ := c.Get("user")
	u := user.(User)
	c.Set("user", u)
	sc, err := a.userHasCorrectAccess(&svRec, &u)
	if err != nil {
		c.JSON(sc, gin.H{"message": err.Error()})
		return
	}
	a.Log.Debug().Msgf("User [%s] has correct access ✓", u.Username)

	// fetch the backup stream from GridFS
	db := a.Mongo.Database(svRec.DBName)
	collection := db.Collection("fs.files")
	ctx := c.Request.Context()
	var fileDoc bson.M
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
	bucket, err := gridfs.NewBucket(db)
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

	// fetch credentials and decrypt
	var crdRec Cred
	crdRec.CredId = svRec.CredId
	res = a.DB.First(&crdRec)
	if res.Error != nil {
		status := http.StatusInternalServerError
		msg := "Something went whump"
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			a.Log.Info().Msgf("Record not found for cred id [%s]", crdRec.CredId.String())
			status = http.StatusNotFound
			msg = "Cred record not found"
		} else {
			a.Log.Info().Msgf("Error finding Cred [%s]", res.Error.Error())
		}
		c.JSON(status, gin.H{"message": msg})
		return
	}
	key := []byte(os.Getenv("SUPERSECRETKEY"))
	nonce := []byte(os.Getenv("SUPERSECRETNONCE"))
	pw, err := utils.Decrypt(crdRec.DBPassword, key, nonce)
	if err != nil {
		a.Log.Info().Msgf("Error decrypting password from creds [%s]", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went plop"})
		return
	}

	// dispatch to the correct restore function
	switch svRec.Type {
	case "postgres":
		a.RestorePostgres(c, &svRec, &crdRec, &pw, downloadStream)
	case "mongo":
		a.RestoreMongo(c, &svRec, &crdRec, &pw, downloadStream)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid save type"})
	}
}

//-----------------------------------------------------------------------------
// Fetch metadata about all saves
//-----------------------------------------------------------------------------

func (a *App) MetadataReport(c *gin.Context) {

	// get all the microservices for which we have a RoleCredMs record.
	var metas []Metadata
	//a.DB = a.DB.Debug()
	sql := `
		WITH stats AS (
		  SELECT
			microservice_id,
			cred_id,
			COUNT(*) AS saved_count,
			SUM(CASE WHEN valid THEN 1 ELSE 0 END) AS valid_count,
			SUM(CASE WHEN NOT valid THEN 1 ELSE 0 END) AS invalid_count,
			MAX(version) AS latest_version
		  FROM save_records
		  GROUP BY microservice_id, cred_id
		)
		SELECT
		  rcms.microservice_id,
		  rcms.cred_id,
		  rcms.role_name,
		  c.db_name,
		  c.type,
		  COALESCE(stats.latest_version, 0) AS latest_version,
		  sr.save_id AS last_save_id,
		  COALESCE(stats.saved_count, 0) AS saved_count,
		  COALESCE(stats.valid_count, 0) AS valid_count,
		  COALESCE(stats.invalid_count, 0) AS invalid_count
		FROM role_cred_ms rcms
		JOIN creds c ON c.cred_id = rcms.cred_id
		LEFT JOIN stats ON stats.microservice_id = rcms.microservice_id AND stats.cred_id = rcms.cred_id
		LEFT JOIN save_records sr
		  ON sr.microservice_id = rcms.microservice_id
		  AND sr.cred_id = rcms.cred_id
		  AND sr.version = stats.latest_version
	`
	res := a.DB.Raw(sql).Scan(&metas)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			a.Log.Info().Msg("No records found that match criteria!")
			c.JSON(http.StatusNotFound, gin.H{"message": "No records found that match criteria"})
			return
		}
		a.Log.Info().Msgf("Error collating data [%s]", res.Error)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went neee"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"no_of_microservices": len(metas), "saved_records_metadata": metas})
	return
}

//-----------------------------------------------------------------------------
// ListAllSaves
//-----------------------------------------------------------------------------

func (a *App) ListAllSaves(c *gin.Context) {

	meta := c.Query("meta")

	if meta != "" && meta != "true" {
		a.Log.Info().Msg("Invalid meta value")
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid meta value"})
		return
	}

	if meta == "true" {
		a.MetadataReport(c)
		return
	}

	// TODO: Deffo need to paginate this
	var allSaves []SaveRecord
	res := a.DB.Order("db_name asc, version desc").Find(&allSaves)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			a.Log.Info().Msg("SaveRecord table is empty!")
			c.JSON(http.StatusNotFound, gin.H{"message": "No save records found"})
			return
		}
		a.Log.Info().Msgf("Error returning data from SaveRecord table [%s]", res.Error)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went neee"})
		return
	}
	if len(allSaves) == 0 {
		a.Log.Info().Msg("SaveRecord table is empty!")
		c.JSON(http.StatusNotFound, gin.H{"message": "No save records found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"total_saves": len(allSaves), "saves": allSaves})

}

//-----------------------------------------------------------------------------
// DeleteByDB
//-----------------------------------------------------------------------------

func (a *App) DeleteByDB(c *gin.Context) {
	c.JSON(http.StatusLocked, gin.H{"message": "Danger! Will Smith; Danger!"})
}

//-----------------------------------------------------------------------------
// RestoreSystemByDataSet
//-----------------------------------------------------------------------------

func (a *App) RestoreSystemByDataSet(c *gin.Context) {
	c.JSON(http.StatusLocked, gin.H{"message": "Danger! Will Smith; Danger!"})
}

//-----------------------------------------------------------------------------
// SystemWipe
//-----------------------------------------------------------------------------

func (a *App) SystemWipe(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "wibble"})
}

//-----------------------------------------------------------------------------
// WipeMicroservice - clears data and schema from microservice
//-----------------------------------------------------------------------------

func (a *App) WipeMicroservice(c *gin.Context) {

	if !utils.IsValidUUIDString(c.Param("msId")) {
		a.Log.Info().Msg("Invalid ms id in url")
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request"})
		return
	}
	msId := c.Param("msId")

	// get cred record from microservice id via RoleCredMS
	// should only be 1. might have to revisit
	var cred Cred
	res := a.DB.
		Table("role_cred_ms").
		Select("creds.*").
		Joins("join creds on creds.cred_id = role_cred_ms.cred_id").
		Where("role_cred_ms.microservice_id = ?", msId).
		First(&cred)
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
	key := []byte(os.Getenv("SUPERSECRETKEY"))
	nonce := []byte(os.Getenv("SUPERSECRETNONCE"))
	pw, err := utils.Decrypt(cred.DBPassword, key, nonce)
	if err != nil {
		a.Log.Info().Msgf("Error decrypting password from creds [%s]", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Error decrypting password from creds"})
		return
	}

	if cred.Type == "postgres" {
		// empty all tables - no need to drop tables
		sc, err := a.PostgresDeleteAllRecs(&cred, &pw)
		if err != nil {
			c.JSON(sc, gin.H{"message": err.Error()})
			return
		}
	} else if cred.Type == "mongo" {
		dropCmd := `db.getCollectionNames().forEach(function(c){db[c].drop();})`
		_, err = a.writeMongoOut(c, dropCmd, &cred, &pw)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to drop all collections before restore"})
			return
		}
		a.Log.Debug().Msg("Dropped all collections")
	}

	c.JSON(http.StatusOK, gin.H{"message": "wibble"})
}

//-----------------------------------------------------------------------------
// DeleteSaveById - delete a particular save
//-----------------------------------------------------------------------------

func (a *App) DeleteSaveById(c *gin.Context) {

	if !utils.IsValidUUIDString(c.Param("saveId")) {
		a.Log.Info().Msg("Invalid save id in url")
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request"})
		return
	}
	saveId, _ := uuid.Parse(c.Param("saveId"))

	svRec := SaveRecord{SaveId: saveId}
	res := a.DB.First(&svRec)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			a.Log.Info().Msgf("SaveRecord record not found for id [%s]", saveId)
			c.JSON(http.StatusNotFound, gin.H{"message": "SaveRecord record not found"})
			return
		}
		a.Log.Info().Msgf("Error finding SaveRecord [%s]", res.Error)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went neee"})
		return
	}

	// delete from mongodb first
	a.Log.Info().Msgf("Save id [%s]; db name [%s]", saveId.String(), svRec.DBName)
	err := a.DeleteGridFSBySaveID(c, saveId.String(), svRec.DBName)
	if err != nil {
		a.Log.Info().Msgf("Error deleting data from mongo [%s]", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went donk"})
		return
	}

	// then delete from postgres
	res = a.DB.Delete(&svRec)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			a.Log.Info().Msgf("SaveRecord record not deleted for id [%s]", saveId)
			c.JSON(http.StatusNotFound, gin.H{"message": "SaveRecord record not deleted"})
			return
		}
		a.Log.Info().Msgf("Error deleting SaveRecord [%s]", res.Error)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went splat"})
		return
	}

	m := fmt.Sprintf("Save record [%s] and mongo data deleted", saveId)
	c.JSON(http.StatusOK, gin.H{"message": m})
}
