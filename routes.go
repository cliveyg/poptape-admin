package main

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"os"
)

func (a *App) initialiseRoutes() {

	a.Log.Info().Msg("Initialising routes")
	a.Router.GET("/admin/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "System running...", "version": os.Getenv("VERSION")})
	})

	a.Router.POST("/admin/login", func(c *gin.Context) {
		a.Login(c)
	})

	a.Router.POST("/admin/user", a.authMiddleware(), a.accessControlMiddleware([]string{"super"}), func(c *gin.Context) {
		a.CreateUser(c)
	})

	a.Router.GET("/admin/test/route", a.authMiddleware(), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.TestRoute(c)
	})

}
