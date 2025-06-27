package main

import (
	"github.com/cliveyg/poptape-admin/utils"
	"github.com/gin-gonic/gin"
	"net/http"
)

func (a *App) initialiseMiddleWare() {
	a.Log.Debug().Msg("Initialising middleware")
	a.Router.Use(a.LoggingMiddleware())
	a.Router.Use(gin.Recovery())
	a.Router.Use(a.auditMiddleware())
}

//-----------------------------------------------------------------------------

func (a *App) auditMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		//Log.Print("auditMiddleware")

		c.Next()
	}
}

//-----------------------------------------------------------------------------

func (a *App) authMiddleware() gin.HandlerFunc {
	a.Log.Debug().Msg("Checking auth")
	return func(c *gin.Context) {
		if !a.hasValidJWT(c) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
			return
		}

		var i interface{}
		i, _ = c.Get("user")
		u := i.(User)
		token, err := utils.GenerateToken(u.Username, u.AdminId)
		if err != nil {
			a.Log.Info().Msgf("Error creating JWT; Error [%s]", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went bang"})
		} else {
			c.Set("token", token)
		}
		// call the next handler
		c.Next()
	}
}

//-----------------------------------------------------------------------------

func accessControlMiddleware(allowedRoles []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if the user has the required role
		role := getUserRole(c)
		if !isRoleAllowed(role, allowedRoles) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden"})
			return
		}

		// Call the next handler
		c.Next()
	}
}

func getUserRole(c *gin.Context) string {
	// Get the user's role from the session or database
	// Example: get the role from the session
	role := c.GetString("role")
	role = "superadmin"
	return role
}

func isRoleAllowed(role string, allowedRoles []string) bool {
	// Check if the user's role is allowed
	for _, allowedRole := range allowedRoles {
		if role == allowedRole {
			return true
		}
	}
	return false
}

//-----------------------------------------------------------------------------

func (a *App) LoggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		a.Log.Debug().Msgf("Route [%s]; Method [%s]; IP [%s]", c.Request.URL.Path, c.Request.Method, c.Request.RemoteAddr)
		c.Next()
	}
}
