package app

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"os"
)

func (a *App) InitialiseRoutes() {

	a.Log.Debug().Msg("Initialising routes")

	//-----------------------------------------------------------------
	// user routes
	//-----------------------------------------------------------------

	// login to admin microservice
	a.Router.POST("/admin/login", func(c *gin.Context) {
		a.Login(c)
	})

	// create user
	a.Router.POST("/admin/user", a.AuthMiddleware(false), a.AccessControlMiddleware([]string{"super"}), func(c *gin.Context) {
		a.CreateUser(c)
	})

	// fetch user deets
	a.Router.GET("/admin/user/:aId", a.AuthMiddleware(false), a.AccessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.FetchUser(c)
	})

	// add a role to user
	a.Router.POST("/admin/user/:aId/:rName", a.AuthMiddleware(false), a.AccessControlMiddleware([]string{"super"}), func(c *gin.Context) {
		a.AddRoleToUser(c)
	})

	// remove role from user
	a.Router.DELETE("/admin/user/:aId/:rName", a.AuthMiddleware(false), a.AccessControlMiddleware([]string{"super"}), func(c *gin.Context) {
		a.RemoveRoleFromUser(c)
	})

	// delete user
	a.Router.DELETE("/admin/user/:aId", a.AuthMiddleware(false), a.AccessControlMiddleware([]string{"super"}), func(c *gin.Context) {
		a.DeleteUser(c)
	})

	// fetch all users
	a.Router.GET("/admin/users", a.AuthMiddleware(false), a.AccessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.FetchAllUsers(c)
	})

	//-----------------------------------------------------------------
	// save/load routes
	//-----------------------------------------------------------------

	// list all saves or returns metadata about saves if meta=true querystring is set
	a.Router.GET("/admin/saves", a.AuthMiddleware(false), a.AccessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.ListAllSaves(c)
	})

	// load db/table by save_id - access control for this is handled in the function itself
	// and not by the standard AccessControlMiddleware() functionality
	a.Router.GET("/admin/load/data/:saveId", a.AuthMiddleware(false), func(c *gin.Context) {
		a.RestoreDBBySaveId(c)
	})

	// delete specific save id
	a.Router.DELETE("/admin/data/:saveId", a.AuthMiddleware(false), a.AccessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.DeleteSaveById(c)
	})

	// backup specific db
	a.Router.GET("/admin/save/:msId/:db", a.AuthMiddleware(true), a.AccessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.BackupDB(c)
	})

	// backup specific db and table/collection
	a.Router.GET("/admin/save/:msId/:db/:tab", a.AuthMiddleware(true), a.AccessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.BackupDB(c)
	})

	// load specific db
	a.Router.GET("/admin/load/:msId/:db", a.AuthMiddleware(true), a.AccessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.Log.Info().Msg("load latest version specific db")
		a.RestoreDB(c)
	})

	// load specific db table/collection
	a.Router.GET("/admin/load/:msId/:db/:tab", a.AuthMiddleware(true), a.AccessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.RestoreDB(c)
	})

	//-----------------------------------------------------------------
	// credentials routes
	//-----------------------------------------------------------------

	// list all creds
	a.Router.GET("/admin/creds", a.AuthMiddleware(false), a.AccessControlMiddleware([]string{"super"}), func(c *gin.Context) {
		a.ListAllCreds(c)
	})

	// create creds record for microservice/db
	a.Router.POST("/admin/creds", a.AuthMiddleware(false), a.AccessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.CreateCreds(c)
	})

	// fetch creds for specific cred id
	a.Router.GET("/admin/creds/:cId", a.AuthMiddleware(false), a.AccessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.FetchCredsById(c)
	})

	//-----------------------------------------------------------------
	// role routes
	//-----------------------------------------------------------------

	// list all roles
	a.Router.GET("/admin/roles", a.AuthMiddleware(false), a.AccessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.ListAllRoles(c)
	})

	//-----------------------------------------------------------------
	// microservice routes
	//-----------------------------------------------------------------

	// list all microservices
	a.Router.GET("/admin/microservices", a.AuthMiddleware(false), a.AccessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.ListMicroservices(c)
	})

	// list all saves by microservice id
	a.Router.GET("/admin/microservice/:msId/saves", a.AuthMiddleware(true), a.AccessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.ListAllSavesByMicroservice(c)
	})

	// clear all data from ms
	// as it currently stands only admin or super can do this
	a.Router.GET("/admin/microservice/:msId/wipe", a.AuthMiddleware(false), a.AccessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.WipeMicroservice(c)
	})

	//-----------------------------------------------------------------
	// aws routes
	//-----------------------------------------------------------------

	// get list of all aws poptape standard users
	a.Router.GET("/admin/aws/users", a.AuthMiddleware(false), a.AccessControlMiddleware([]string{"super", "admin", "aws"}), func(c *gin.Context) {
		a.ListAllPoptapeStandardUsers(c)
	})

	// get list of all aws poptape standard users
	a.Router.GET("/admin/aws/buckets", a.AuthMiddleware(false), a.AccessControlMiddleware([]string{"super", "admin", "aws"}), func(c *gin.Context) {
		a.ListAllPoptapeStandardBuckets(c)
	})

	//-----------------------------------------------------------------
	// superuser routes
	//-----------------------------------------------------------------

	// wipe entire system - use carefully
	a.Router.GET("/admin/clearall", a.AuthMiddleware(false), a.AccessControlMiddleware([]string{"super"}), func(c *gin.Context) {
		a.SystemWipe(c)
	})

	// load entire system based on the dataset number - superuser only
	a.Router.GET("/admin/load/dataset/:dset", a.AuthMiddleware(false), a.AccessControlMiddleware([]string{"super"}), func(c *gin.Context) {
		a.RestoreSystemByDataSet(c)
	})

	// delete all mongo records and set all postgres records for db to invalid - superuser only
	a.Router.DELETE("/admin/:msId/:db", a.AuthMiddleware(false), a.AccessControlMiddleware([]string{"super"}), func(c *gin.Context) {
		a.DeleteByDB(c)
	})

	//-----------------------------------------------------------------
	// system, status and test routes
	//-----------------------------------------------------------------

	// fetch admin microservice status
	a.Router.GET("/admin/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "System running...", "version": os.Getenv("VERSION")})
	})

	// all other routes
	a.Router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"message": "Resource not found"})
	})

}
