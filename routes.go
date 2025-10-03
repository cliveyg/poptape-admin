package main

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"os"
)

func (a *App) InitialiseRoutes() {

	a.Log.Info().Msg("Initialising routes")

	// fetch admin microservice status
	a.Router.GET("/admin/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "System running...", "version": os.Getenv("VERSION")})
	})

	// login to admin microservice
	a.Router.POST("/admin/login", func(c *gin.Context) {
		a.Login(c)
	})

	// list all microservices
	a.Router.GET("/admin/microservices", a.authMiddleware(false), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.ListMicroservices(c)
	})

	// backup specific db and table/collection
	a.Router.GET("/admin/save/:msId/:db/:tab", a.authMiddleware(true), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.Log.Info().Msg("First path")
		a.BackupDB(c)
	})

	// backup specific db
	a.Router.GET("/admin/save/:msId/:db", a.authMiddleware(true), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.Log.Info().Msg("Should get here")
		a.BackupDB(c)
	})

	// load specific db table/collection
	a.Router.GET("/admin/load/:msId/:db/:tab", a.authMiddleware(true), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.Log.Info().Msg("First path")
		a.RestoreDB(c)
	})

	// load specific db
	a.Router.GET("/admin/load/:msId/:db", a.authMiddleware(true), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.Log.Info().Msg("Should get here")
		a.RestoreDB(c)
	})

	// create creds record for microservice/db
	a.Router.POST("/admin/creds", a.authMiddleware(false), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.CreateCreds(c)
	})

	// fetch creds for specific cred id
	a.Router.GET("/admin/creds/:cId", a.authMiddleware(false), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.FetchCredsById(c)
	})

	// list all creds
	a.Router.GET("/admin/creds", a.authMiddleware(false), a.accessControlMiddleware([]string{"super"}), func(c *gin.Context) {
		a.ListAllCreds(c)
	})

	// list all roles
	a.Router.GET("/admin/roles", a.authMiddleware(false), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.ListAllRoles(c)
	})

	// create user
	a.Router.POST("/admin/user", a.authMiddleware(false), a.accessControlMiddleware([]string{"super"}), func(c *gin.Context) {
		a.CreateUser(c)
	})

	// fetch user deets
	a.Router.GET("/admin/user/:aId", a.authMiddleware(false), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.FetchUser(c)
	})

	// add a role to user
	a.Router.POST("/admin/user/:aId/:rName", a.authMiddleware(false), a.accessControlMiddleware([]string{"super"}), func(c *gin.Context) {
		a.AddRoleToUser(c)
	})

	// remove role from user
	a.Router.DELETE("/admin/user/:aId/:rName", a.authMiddleware(false), a.accessControlMiddleware([]string{"super"}), func(c *gin.Context) {
		a.RemoveRoleFromUser(c)
	})

	// edit users
	a.Router.PUT("/admin/user/:aId", a.authMiddleware(false), a.accessControlMiddleware([]string{"super"}), func(c *gin.Context) {
		a.EditUser(c)
	})

	// delete user
	a.Router.DELETE("/admin/user/:aId", a.authMiddleware(false), a.accessControlMiddleware([]string{"super"}), func(c *gin.Context) {
		a.DeleteUser(c)
	})

	// fetch all users
	a.Router.GET("/admin/users", a.authMiddleware(false), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.FetchAllUsers(c)
	})

	// test route
	a.Router.GET("/admin/test/pgdump", a.authMiddleware(false), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.TestRoute(c)
	})

	// test route
	//a.Router.GET("/admin/test/access/:msId", a.authMicroserviceMiddleware(true), a.accessControlMicroserviceMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
	//	a.Testy(c)
	//})

	// get aws deets
	a.Router.GET("/admin/aws/:awsId", a.authMiddleware(false), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.FetchAWSDetails(c)
	})

	// wipe entire system - use carefully
	a.Router.GET("/admin/clearall", a.authMiddleware(false), a.accessControlMiddleware([]string{"super"}), func(c *gin.Context) {
		a.SystemWipe(c)
	})

	a.Router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"message": "Resource not found"})
	})

}
