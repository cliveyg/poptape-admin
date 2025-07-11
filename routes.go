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

	a.Router.GET("/admin/savedb/:msId/:db/:tab", a.authMiddleware(), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.Log.Info().Msg("First path")
		a.BackupDB(c)
	})

	a.Router.GET("/admin/savedb/:msId/:db", a.authMiddleware(), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.Log.Info().Msg("Should get here")
		a.BackupDB(c)
	})

	a.Router.POST("/admin/creds", a.authMiddleware(), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.CreateCreds(c)
	})

	a.Router.GET("/admin/creds/:cId", a.authMiddleware(), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.FetchCreds(c)
	})

	a.Router.POST("/admin/user", a.authMiddleware(), a.accessControlMiddleware([]string{"super"}), func(c *gin.Context) {
		a.CreateUser(c)
	})

	a.Router.GET("/admin/user/:aId", a.authMiddleware(), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.FetchUser(c)
	})

	a.Router.POST("/admin/user/:aId/:rName", a.authMiddleware(), a.accessControlMiddleware([]string{"super"}), func(c *gin.Context) {
		a.AddRoleToUser(c)
	})

	a.Router.DELETE("/admin/user/:aId", a.authMiddleware(), a.accessControlMiddleware([]string{"super"}), func(c *gin.Context) {
		a.DeleteUser(c)
	})

	a.Router.GET("/admin/users", a.authMiddleware(), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.FetchAllUsers(c)
	})

	a.Router.GET("/admin/test/route", a.authMiddleware(), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.TestRoute(c)
	})

	a.Router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"message": "Resource not found"})
	})

}
