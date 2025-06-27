package main

import (
	"fmt"
	"github.com/cliveyg/poptape-admin/utils"
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

//-----------------------------------------------------------------------------

func (a *App) CreateUser(c *gin.Context) {
	a.Log.Debug().Msg("All valid and in TestRoute")
	var su Signup
	err := c.ShouldBindJSON(&su)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request [1]"})
		a.Log.Info().Msgf("Signup failed: [%s]", err.Error())
		return
	}
	if su.Password != su.ConfirmPassword {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Passwords don't match"})
		a.Log.Info().Msgf("Signup failed: [%s]", err.Error())
		return
	}
	var epw []byte
	epw, err = utils.GenerateHashPassword(su.Password)
	u := User{Username: su.Username, Password: epw}
	a.Log.Info().Interface("User: ", u).Send()
	res := a.DB.Create(&u)
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went bang [1]"})
		a.Log.Info().Msgf("Signup failed: [%s]", err.Error())
		return
	}
	// by default only add user to admin role
	ur := UserRole{AdminId: u.AdminId, RoleName: "admin"}
	res = a.DB.Create(&ur)
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went bang [2]"})
		a.Log.Info().Msgf("Signup failed: [%s]", err.Error())
		return
	}

	// validate user
	u.Validated = true
	res = a.DB.Save(&u)
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went bang [3]"})
		a.Log.Info().Msgf("Signup failed: [%s]; Unable to validate user [%s]", err.Error(), u.Username)
		return
	}

	c.Header("y-access-token", c.GetString("token"))
	ms := fmt.Sprintf("User [%s] created and validated; Id is [%s]", u.Username, u.AdminId.String())
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
	} else {

		u := User{Username: lg.Username}
		if a.checkLoginDetails(&lg, &u) != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Username or password incorrect"})
		} else {
			a.Log.Debug().Msg("Login OK; Creating JWT")
			token, err := utils.GenerateToken(u.Username, u.AdminId)
			if err != nil {
				a.Log.Info().Msgf("Error creating JWT; Error [%s]", err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went bang"})
			} else {
				u.LastLogin = time.Now()
				res := a.DB.Save(&u)
				if res.Error != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"message": "Ooops"})
					a.Log.Info().Msgf("Unable to update user last login: [%s]", err.Error())
					return
				}
				c.JSON(http.StatusOK, gin.H{"token": token})
			}
		}
	}
}

//-----------------------------------------------------------------------------
