package main

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"os"
)

func (a *App) initializeRoutes() {

	a.Router.GET("/admin/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "System running...", "version": os.Getenv("VERSION")})
	})

	a.Router.POST("/admin/login", func(c *gin.Context) {
		//Log.Print("/admin/login called")
		//if a.logInOK
		//c.JSON(http.StatusOK, gin.H{"message": "System running...", "version": "0.1.0"})
	})

}
