package app

import (
	"context"
	"errors"
	"fmt"
	"github.com/cliveyg/poptape-admin/awsutil"
	"github.com/cliveyg/poptape-admin/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"net/http"
	"os"
)

//-----------------------------------------------------------------------------
// InitialiseMiddleWare
//-----------------------------------------------------------------------------

func (a *App) InitialiseMiddleWare() {
	a.Log.Debug().Msg("Initialising middleware")
	a.Router.Use(a.LoggingMiddleware())
	a.Router.Use(gin.Recovery())
	a.Router.Use(a.auditMiddleware())
}

//-----------------------------------------------------------------------------
// auditMiddleware
//-----------------------------------------------------------------------------

func (a *App) auditMiddleware() gin.HandlerFunc {

	return func(c *gin.Context) {
		if os.Getenv("ENVIRONMENT") == "PROD" {

		}
		c.Next()
	}
}

//-----------------------------------------------------------------------------
// AuthMiddleware
//-----------------------------------------------------------------------------

func (a *App) AuthMiddleware(msExists bool) gin.HandlerFunc {

	// msExists controls if we add the role for the microservice being called
	// to the allowed roles before we check against the user. this enables us
	// to use the same piece of code without hardcoding the access to where
	// the gin framework controls access. stops someone with, for example,
	// apiserver microservice backup/restore access being able to backup/restore
	// the reviews microservice

	return func(c *gin.Context) {

		if !a.hasValidJWT(c) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
			return
		}

		if msExists {
			msId, err := uuid.Parse(c.Param("msId"))
			if err != nil {
				a.Log.Info().Msgf("Invalid ms id in url [%s]", err.Error())
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"message": "Bad request [ms]"})
				return
			}

			rcms := RoleCredMS{}
			res := a.DB.Where("microservice_id = ?", msId).First(&rcms)
			if res.Error != nil {
				if errors.Is(res.Error, gorm.ErrRecordNotFound) {
					a.Log.Info().Msgf("RoleCredMS not found for ms [%s]", msId)
					c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"message": "RoleCredMS record not found"})
					return
				}
				a.Log.Info().Msgf("Error finding RoleCredMS [%s]", res.Error.Error())
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"message": "Something went whump"})
				return
			}
			a.Log.Debug().Msgf("RoleCredMS is [%s]", rcms)
			c.Set("role", rcms.RoleName)
			c.Set("cred_id", rcms.CredId)
			c.Set("ms_id", rcms.MicroserviceId)
		}

		var i interface{}
		i, _ = c.Get("user")
		u := i.(User)
		// as getting consumes the resource we have to reset it
		c.Set("user", u)
		token, err := utils.GenerateToken(u.Username, u.AdminId)
		if err != nil {
			a.Log.Info().Msgf("Error creating JWT; Error [%s]", err.Error())
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"message": "Something went bang"})
		} else {
			c.Set("token", token)
		}

		c.Next()
	}
}

//-----------------------------------------------------------------------------
// AccessControlMiddleware
//-----------------------------------------------------------------------------

func (a *App) AccessControlMiddleware(allowedRoles []string) gin.HandlerFunc {

	return func(c *gin.Context) {
		var i interface{}
		i, _ = c.Get("user")
		u := i.(User)
		// as getting consumes the resource we have to reset it
		c.Set("user", u)

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
// LoggingMiddleware
//-----------------------------------------------------------------------------

func (a *App) LoggingMiddleware() gin.HandlerFunc {

	return func(c *gin.Context) {
		a.Log.Debug().Msgf("Route [%s]; Method [%s]; IP [%s]", c.Request.URL.Path, c.Request.Method, c.Request.RemoteAddr)
		c.Next()
	}
}

//-----------------------------------------------------------------------------
// InitialiseAWS
//-----------------------------------------------------------------------------

func (a *App) InitialiseAWS() {
	ctx := context.Background()
	awsAdmin, err := awsutil.NewAWSAdmin(ctx, a.Log)
	if err != nil {
		a.Log.Fatal().Err(err).Msg("Failed to initialise AWS ✗")
	}

	if awsAdmin == nil {
		a.Log.Fatal().Msg("AWSAdmin is nil after initialization ✗")
	}
	a.Log.Debug().Msg("AWS connection initialised ✓")

	if err = awsAdmin.TestConnection(ctx); err != nil {
		a.Log.Fatal().Err(err).Msg("Failed to connect to AWS ✗")
	}

	a.Log.Debug().Msg("Connected to AWS ✓")
	a.AWS = awsAdmin
}
