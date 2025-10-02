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
	"os/exec"
	"slices"
)

//-----------------------------------------------------------------------------

func (a *App) ListAllCreds(c *gin.Context) {
	var crds []Cred
	res := a.DB.Find(&crds)
	if res.Error != nil {
		a.Log.Info().Msgf("Error returning creds [%s]", res.Error.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went nope"})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"message": "No creds found"})
		return
	}
	for i := range crds {
		crds[i].DBPassword = "XXXX"
	}
	c.JSON(http.StatusOK, gin.H{"creds": crds})
}

//-----------------------------------------------------------------------------

func (a *App) FetchCredsById(c *gin.Context) {

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
		a.Log.Info().Msgf("Error finding creds [%s]", res.Error.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went neee"})
		return
	}

	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"message": "Creds not found"})
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

	// Get password from environment variable
	pgPassword := os.Getenv("POPTAPE_REVIEW_PASSWORD")
	if pgPassword == "" {
		a.Log.Info().Msg("Environment variable POPTAPE_REVIEW_PASSWORD is not set")
		c.JSON(http.StatusServiceUnavailable, gin.H{"message": "Environment variable not set"})
		return
	}

	// pg_dump command arguments
	args := []string{
		"-h", "poptape-reviews-db-1", // Host (container name or IP)
		"-U", "poptape_reviews", // Username
		"-p", "5432",
		"poptape_reviews", // Database name
	}

	cmd := exec.Command("pg_dump", args...)
	cmd.Env = append(os.Environ(), "PGPASSWORD="+pgPassword)

	// Optional: Output the result to a file
	outFile, err := os.Create("dump.sql")
	if err != nil {
		a.Log.Info().Msgf("Error creating dump file [%s]", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Error creating dump file"})
		return
	}
	defer outFile.Close()
	cmd.Stdout = outFile

	// Run the command
	if err := cmd.Run(); err != nil {
		a.Log.Info().Msgf("pg_dump failed [%s]", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "pg_dump failed"})
		return
	}

	a.Log.Info().Msg("Database dumped successfully to dump.sql")

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
	var msId uuid.UUID
	var err error
	dbName := ""
	tabColl := ""
	m := c.Query("mode")

	vl := []string{"schema", "all", "data"}
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
	tabColl = c.Param("tabColl")

	a.Log.Debug().Msgf("Input vars are: msId [%s], db [%s], tabColl [%s], mode [%s]", msId.String(), dbName, tabColl, m)
	c.JSON(http.StatusTeapot, gin.H{"message": "Moop"})

	ms := Microservice{MicroserviceId: msId}
	res := a.DB.First(&ms, msId)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			a.Log.Info().Msgf("Microservice [%s] not found", msId.String())
			c.JSON(http.StatusNotFound, gin.H{"message": "Microservice not found"})
			return
		}
		a.Log.Info().Msgf("Error finding microservice [%s]", res.Error)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went neee"})
		return
	}

	// got the microservice

}

//-----------------------------------------------------------------------------

func (a *App) RestoreDB(c *gin.Context) {

	a.Log.Debug().Msg("In RestoreDB")
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

//-----------------------------------------------------------------------------

func (a *App) ListMicroservices(c *gin.Context) {
	var mss []Microservice
	var u User
	//var vr bool
	if value, exists := c.Get("user"); exists {
		u = value.(User)
	}
	//vr = a.userHasValidRole(u.Roles, []string{"super", "admin"})
	a.Log.Info().Interface("User", u).Send()
	if a.userHasValidRole(u.Roles, []string{"super", "admin"}) {
		a.Log.Debug().Msg("User has a valid role")
	}

	res := a.DB.Find(&mss)
	if res.Error != nil || len(mss) == 0 {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) || len(mss) == 0 {
			c.JSON(http.StatusNotFound, gin.H{"message": "No microservices found"})
			return
		}
		a.Log.Info().Msgf("Error finding microservices [%s]", res.Error)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went neee"})
		return
	}

	/*
		var msma map[string]map[string]interface{}
		for i := 0; i < len(mss); i++ {
			mp := utils.StructToMap(mss[i])
			msma["k"+string(rune(i))] = mp
		}
	*/
	c.JSON(http.StatusOK, gin.H{"microservices": mss})

}

//-----------------------------------------------------------------------------

func (a *App) ListAllRoles(c *gin.Context) {
	var mss []Microservice
	var u User
	//var vr bool
	if value, exists := c.Get("user"); exists {
		u = value.(User)
	}
	//vr = a.userHasValidRole(u.Roles, []string{"super", "admin"})
	a.Log.Info().Interface("User", u).Send()
	if a.userHasValidRole(u.Roles, []string{"super", "admin"}) {
		a.Log.Debug().Msg("User has a valid role")
	}

	res := a.DB.Find(&mss)
	if res.Error != nil || len(mss) == 0 {
		a.Log.Info().Msgf("Error finding microservices [%s]", res.Error)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went neee"})
		return
	}

	if res.RowsAffected == 0 {
		a.Log.Info().Msgf("No roles found!")
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went neee"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"roles": mss})
}

//-----------------------------------------------------------------------------

func (a *App) SystemWipe(c *gin.Context) {

}

//-----------------------------------------------------------------------------
