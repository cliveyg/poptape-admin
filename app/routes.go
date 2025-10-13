package app

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"os"
)

func (a *App) InitialiseRoutes() {

	a.Log.Info().Msg("Initialising routes")

	//-----------------------------------------------------------------
	// user routes
	//-----------------------------------------------------------------

	// login to admin microservice
	a.Router.POST("/admin/login", func(c *gin.Context) {
		a.Login(c)
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

	//-----------------------------------------------------------------
	// save/load routes
	//-----------------------------------------------------------------

	// list all saves or returns metadata about saves if meta=true querystring is set
	a.Router.GET("/admin/saves", a.authMiddleware(false), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.ListAllSaves(c)
	})

	// load db/table by save_id - access control for this is handled in the function itself
	// and not by the standard accessControlMiddleware() functionality
	a.Router.GET("/admin/load/data/:saveId", a.authMiddleware(false), func(c *gin.Context) {
		a.RestoreDBBySaveId(c)
	})

	// delete specific save id
	a.Router.DELETE("/admin/data/:saveId", a.authMiddleware(false), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.DeleteSaveById(c)
	})

	// backup specific db
	a.Router.GET("/admin/save/:msId/:db", a.authMiddleware(true), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.BackupDB(c)
	})

	// backup specific db and table/collection
	a.Router.GET("/admin/save/:msId/:db/:tab", a.authMiddleware(true), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.BackupDB(c)
	})

	// load specific db
	a.Router.GET("/admin/load/:msId/:db", a.authMiddleware(true), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.Log.Info().Msg("load latest version specific db")
		a.RestoreDB(c)
	})

	// load specific db table/collection
	a.Router.GET("/admin/load/:msId/:db/:tab", a.authMiddleware(true), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.RestoreDB(c)
	})

	//-----------------------------------------------------------------
	// credentials routes
	//-----------------------------------------------------------------

	// list all creds
	a.Router.GET("/admin/creds", a.authMiddleware(false), a.accessControlMiddleware([]string{"super"}), func(c *gin.Context) {
		a.ListAllCreds(c)
	})

	// create creds record for microservice/db
	a.Router.POST("/admin/creds", a.authMiddleware(false), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.CreateCreds(c)
	})

	// fetch creds for specific cred id
	a.Router.GET("/admin/creds/:cId", a.authMiddleware(false), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.FetchCredsById(c)
	})

	//-----------------------------------------------------------------
	// role routes
	//-----------------------------------------------------------------

	// list all roles
	a.Router.GET("/admin/roles", a.authMiddleware(false), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.ListAllRoles(c)
	})

	//-----------------------------------------------------------------
	// microservice routes
	//-----------------------------------------------------------------

	// list all microservices
	a.Router.GET("/admin/microservices", a.authMiddleware(false), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.ListMicroservices(c)
	})

	// list all saves by microservice id
	a.Router.GET("/admin/microservice/:msId/saves", a.authMiddleware(true), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.ListAllSavesByMicroservice(c)
	})

	// clear all data from ms
	// as it currently stands only admin or super can do this
	a.Router.GET("/admin/microservice/:msId/wipe", a.authMiddleware(false), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.WipeMicroservice(c)
	})

	//-----------------------------------------------------------------
	// aws routes
	//-----------------------------------------------------------------

	// get list of all aws poptape standard users
	a.Router.GET("/admin/aws/users", a.authMiddleware(false), a.accessControlMiddleware([]string{"super", "admin", "poptape_aws"}), func(c *gin.Context) {
		a.ListAllPoptapeStandardUsers(c)
	})

	// get list of all aws poptape standard users
	a.Router.GET("/admin/aws/buckets", a.authMiddleware(false), a.accessControlMiddleware([]string{"super", "admin", "poptape_aws"}), func(c *gin.Context) {
		a.ListAllPoptapeStandardBuckets(c)
	})

	//-----------------------------------------------------------------
	// superuser routes
	//-----------------------------------------------------------------

	// wipe entire system - use carefully
	a.Router.GET("/admin/clearall", a.authMiddleware(false), a.accessControlMiddleware([]string{"super"}), func(c *gin.Context) {
		a.SystemWipe(c)
	})

	// load entire system based on the dataset number - superuser only
	a.Router.GET("/admin/load/dataset/:dset", a.authMiddleware(false), a.accessControlMiddleware([]string{"super"}), func(c *gin.Context) {
		a.RestoreSystemByDataSet(c)
	})

	// delete all mongo records and set all postgres records for db to invalid - superuser only
	a.Router.DELETE("/admin/:msId/:db", a.authMiddleware(false), a.accessControlMiddleware([]string{"super"}), func(c *gin.Context) {
		a.DeleteByDB(c)
	})

	//-----------------------------------------------------------------
	// system, status and test routes
	//-----------------------------------------------------------------

	// fetch admin microservice status
	a.Router.GET("/admin/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "System running...", "version": os.Getenv("VERSION")})
	})

	// test route
	a.Router.GET("/admin/test/pgdump", a.authMiddleware(false), a.accessControlMiddleware([]string{"super", "admin"}), func(c *gin.Context) {
		a.TestRoute(c)
	})

	// all other routes
	a.Router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"message": "Resource not found"})
	})

}
