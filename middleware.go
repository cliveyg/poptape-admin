package main

import (
	"fmt"
	"github.com/cliveyg/poptape-admin/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"net/http"
	"os"
)

func (a *App) InitialiseMiddleWare() {
	a.Log.Debug().Msg("Initialising middleware")
	a.Router.Use(a.LoggingMiddleware())
	a.Router.Use(gin.Recovery())
	a.Router.Use(a.auditMiddleware())
}

//-----------------------------------------------------------------------------

func (a *App) auditMiddleware() gin.HandlerFunc {

	return func(c *gin.Context) {
		//Log.Print("auditMiddleware")
		if os.Getenv("ENVIRONMENT") == "PROD" {

		}

		c.Next()
	}
}

//-----------------------------------------------------------------------------

func (a *App) authMiddleware() gin.HandlerFunc {

	return func(c *gin.Context) {
		if !a.hasValidJWT(c) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
			return
		}

		var i interface{}
		i, _ = c.Get("user")
		u := i.(User)
		// as getting consumes the resource we have to reset it
		c.Set("user", u)
		token, err := utils.GenerateToken(u.Username, u.AdminId)
		if err != nil {
			a.Log.Info().Msgf("Error creating JWT; Error [%s]", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went bang"})
		} else {
			c.Set("token", token)
		}

		c.Next()
	}
}

//-----------------------------------------------------------------------------

func (a *App) authAccessTest() gin.HandlerFunc {

	return func(c *gin.Context) {
		if !a.hasValidJWT(c) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
			return
		}

		msId, err := uuid.Parse(c.Param("msId"))
		if err != nil {
			a.Log.Info().Msgf("Invalid ms id in url [%s]", err.Error())
			c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request"})
			return
		}

		rcms := RoleCredMS{}
		res := a.DB.Where("microservice_id = ?", msId).First(&rcms)
		if res.Error != nil {
			a.Log.Info().Msgf("Error finding microservice [%s]", res.Error.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went whump"})
			return
		}
		if res.RowsAffected == 0 {
			c.JSON(http.StatusNotFound, gin.H{"message": "Role not found for MS"})
			return
		}
		c.Set("role", rcms.RoleName)

		var i interface{}
		i, _ = c.Get("user")
		u := i.(User)
		// as getting consumes the resource we have to reset it
		c.Set("user", u)
		token, err := utils.GenerateToken(u.Username, u.AdminId)
		if err != nil {
			a.Log.Info().Msgf("Error creating JWT; Error [%s]", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went bang"})
		} else {
			c.Set("token", token)
		}

		c.Next()
	}
}

//-----------------------------------------------------------------------------

func (a *App) accessControlMiddleware(allowedRoles []string) gin.HandlerFunc {

	return func(c *gin.Context) {
		var i interface{}
		i, _ = c.Get("user")
		u := i.(User)

		if !a.userHasValidRole(u.Roles, allowedRoles) {
			a.Log.Info().Msgf("User [%s] forbidden to use [%s]", u.Username, c.Request.URL)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"message": "Forbidden"})
			return
		}

		c.Next()
	}
}

//-----------------------------------------------------------------------------

func (a *App) accessControlMiddlewareTest(allowedRoles []string) gin.HandlerFunc {

	return func(c *gin.Context) {

		var i interface{}
		i, _ = c.Get("user")
		u := i.(User)

		ir, _ := c.Get("role")
		if ir != nil {
			allowedRoles = append(allowedRoles, fmt.Sprintf("%v", ir))
		}

		if !a.userHasValidRole(u.Roles, allowedRoles) {
			a.Log.Info().Msgf("User [%s] forbidden to use [%s]", u.Username, c.Request.URL)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"message": "Forbidden"})
			return
		}

		c.Next()
	}
}

//-----------------------------------------------------------------------------

func (a *App) LoggingMiddleware() gin.HandlerFunc {

	return func(c *gin.Context) {
		a.Log.Debug().Msgf("Route [%s]; Method [%s]; IP [%s]", c.Request.URL.Path, c.Request.Method, c.Request.RemoteAddr)
		c.Next()
	}
}
