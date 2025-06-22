package main

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

func (a *App) initializeRoutes() {

	//a.Router.GET("/admin/status", a.LoggingMiddleware(), func(c *gin.Context) {
	a.Router.GET("/admin/status", func(c *gin.Context) {

		//Log.Print("/admin/status called")
		c.JSON(http.StatusOK, gin.H{"message": "System running...", "version": "0.1.0"})
	})

	a.Router.POST("/admin/login", func(c *gin.Context) {
		//Log.Print("/admin/login called")
		//if a.logInOK
		//c.JSON(http.StatusOK, gin.H{"message": "System running...", "version": "0.1.0"})
	})

}
