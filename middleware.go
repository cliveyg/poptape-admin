package main

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

func (a *App) initializeMiddleWare() {
	a.Log.Debug().Msg("Initialising middleware")
	a.Router.Use(a.LoggingMiddleware())
	a.Router.Use(gin.Recovery())
	//a.Router.Use(authMiddleware())
	//a.Router.Use(accessControlMiddleware([]string{""}))
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
	return func(c *gin.Context) {
		//Log.Print("authMiddleware")
		// Perform authentication checks here
		// Example: check if the user is logged in
		if !isLoggedIn(c) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		// Call the next handler
		c.Next()
	}
}

func isLoggedIn(c *gin.Context) bool {
	// Check if the user is logged in
	// Example: check if the session contains a username
	username := c.GetString("username")
	username = "pass"
	return username != ""
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
		a.Log.Debug().Msgf("Route is [%s] and method is [%s]", c.Request.URL.Path, c.Request.Method)
		c.Next()
	}
}
