package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/cliveyg/poptape-admin/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"os"
	"slices"
)

type YHeader struct {
	TokenString string `header:"y-access-token" binding:"required"`
}

//-----------------------------------------------------------------------------

func (a *App) checkLoginDetails(l *Login, u *User) error {

	res := a.DB.Preload("Roles").First(&u, "username = ?", l.Username)
	if res.Error != nil {
		a.Log.Info().Msgf("Login attempted with user [%s]", l.Username)
		a.Log.Error().Msgf("Error: [%s]", res.Error)
		return res.Error
	}
	if !u.Validated {
		a.Log.Info().Msgf("User [%s]: not validated", u.Username)
		return errors.New("user not validated")
	}
	if !u.Active {
		a.Log.Info().Msgf("User [%s]: not active", u.Username)
		return errors.New("user not active")
	}
	pass, err := base64.StdEncoding.DecodeString(l.Password)
	if err != nil {
		a.Log.Info().Msgf("Base64 decoding failed [%s]", err.Error())
		return err
	}
	if !utils.VerifyPassword(pass, u.Password) {
		a.Log.Info().Msgf("User [%s]: password incorrect", u.Username)
		return errors.New("password doesn't match")
	}

	return nil
}

//-----------------------------------------------------------------------------

func (a *App) hasValidJWT(c *gin.Context) bool {

	var y YHeader
	var err error
	if err = c.ShouldBindHeader(&y); err != nil {
		a.Log.Info().Msg("Missing y-access-token")
		a.Log.Debug().Msgf("Unable to bind y-access-token header [%s]", err.Error())
		return false
	}

	var claims *utils.Claims
	claims, err = utils.ParseToken(y.TokenString)
	if err != nil {
		a.Log.Info().Msgf("Failure to parse token [%s]", err.Error())
		return false
	}

	var aId uuid.UUID
	aId, err = uuid.Parse(claims.AdminId)
	if err != nil {
		a.Log.Info().Msgf("Failure to parse token; Invalid admin UUID")
		return false
	}

	u := User{Username: claims.Username, AdminId: aId}

	res := a.DB.Preload("Roles").Find(&u)
	if res.Error != nil {
		a.Log.Info().Msgf("Failed jwt validation with username [%s]", u.Username)
		a.Log.Error().Msgf("Error: [%s]", res.Error)
		return false
	}
	if u.Validated {
		c.Set("user", u)
		return true
	}
	a.Log.Info().Msgf("Failed jwt validation; user [%s] not validated", u.Username)
	return false
}

//-----------------------------------------------------------------------------

func (a *App) userHasValidRole(roles []Role, allowedRoles []string) bool {

	rf := false
	for i := 0; i < len(roles); i++ {
		if slices.Contains(allowedRoles, roles[i].Name) {
			rf = true
			break
		}
	}
	return rf
}

//-----------------------------------------------------------------------------

func (a *App) testEncryptDecrypt(s string) {
	key := []byte(os.Getenv("SUPERSECRETKEY"))
	nonce := []byte(os.Getenv("SUPERSECRETNONCE"))

	var es string
	var err error
	es, err = utils.Encrypt([]byte(s), key, nonce)
	if err != nil {
		a.Log.Error().Msg(err.Error())
	}
	a.Log.Debug().Msgf("Encrypted string is [%s]", es)
	a.Log.Info().Msg("Attempting to decrypt")

	var ba []byte
	ba, err = utils.Decrypt(es, key, nonce)
	if err != nil {
		a.Log.Error().Msg(err.Error())
	}
	if s == string(ba) {
		a.Log.Debug().Msgf("Decrypted string is same as original")
	} else {
		a.Log.Debug().Msgf("Error in encryption/decryption process")
	}
}

//-----------------------------------------------------------------------------

func (a *App) encryptCredPass(cr *Cred) error {
	// decode input password, encrypt it and put it back in same field
	p64, err := base64.StdEncoding.DecodeString(cr.DBPassword)
	if err != nil {
		a.Log.Info().Msgf("Base64 decoding failed [%s]", err.Error())
		return errors.New(fmt.Sprintf("Base64 decoding failed [%s]", err.Error()))
	}
	var est string
	est, err = utils.Encrypt(p64, []byte(os.Getenv("SUPERSECRETKEY")), []byte(os.Getenv("SUPERSECRETNONCE")))
	if err != nil {
		a.Log.Info().Msgf("Encryption failed [%s]", err.Error())
		return errors.New(fmt.Sprintf("Encryption failed [%s]", err.Error()))
	}
	cr.DBPassword = est
	return nil
}

func (a *App) getRoleDetails(c *gin.Context, u *User, rName *string) error {
	adminId, err := uuid.Parse(c.Param("aId"))
	if err != nil {
		a.Log.Info().Msgf("Not a uuid string: [%s]", err.Error())
		return err
	}
	*rName = c.Param("rName")
	if len(*rName) > 20 {
		a.Log.Info().Msg("Role name is too long")
		return errors.New("role name is too long")
	}

	u.AdminId = adminId
	res := a.DB.Preload("Roles").Find(&u)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			a.Log.Info().Msgf("User [%s] not found", u.AdminId.String())
			return res.Error
		}
		a.Log.Info().Msgf("Error finding user [%s]", res.Error)
		return res.Error
	}

	if u.Username == "" {
		return errors.New("user not found")
	}
	return nil
}
