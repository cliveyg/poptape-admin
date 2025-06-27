package main

import (
	"errors"
	"github.com/cliveyg/poptape-admin/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type YHeader struct {
	TokenString string `header:"y-access-token" binding:"required"`
}

//-----------------------------------------------------------------------------

func (a *App) checkLoginDetails(l *Login, u *User) error {

	res := a.DB.First(&u)
	if res.Error != nil {
		a.Log.Info().Msgf("Login attempted with user [%s]", l.Username)
		a.Log.Error().Msgf("Error: [%s]", res.Error)
		return res.Error
	}
	if !u.Validated {
		a.Log.Info().Msgf("User [%s]: not validated", u.Username)
		return errors.New("user not validated")
	}

	if !utils.VerifyPassword(l.Password, u.Password) {
		a.Log.Info().Msgf("User [%s]: password incorrect", u.Username)
		return errors.New("password doesn't match")
	}

	return nil
}

//-----------------------------------------------------------------------------

func (a *App) hasValidJWT(c *gin.Context) bool {

	var y YHeader
	err := c.ShouldBindHeader(&y)
	if err != nil {
		a.Log.Info().Msg("Missing y-access-token")
		a.Log.Debug().Msgf("Unable to bind y-access-token header [%s]", err.Error())
		return false
	}

	claims, err := utils.ParseToken(y.TokenString)
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

	res := a.DB.First(&u)
	if res.Error != nil {
		a.Log.Info().Msgf("Failed login attempted with username [%s]", u.Username)
		a.Log.Error().Msgf("Error: [%s]", res.Error)
		return false
	}
	if u.Validated {
		c.Set("user", u)
		return true
	}
	a.Log.Info().Msgf("Failed login; user [%s] not validated", u.Username)
	return false
}
