package main

import (
	"github.com/cliveyg/poptape-admin/utils"
	"github.com/gin-gonic/gin"
	"net/http"
	"os"
)

func (a *App) initializeRoutes() {

	a.Router.GET("/admin/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "System running...", "version": os.Getenv("VERSION")})
	})

	a.Router.POST("/admin/login", func(c *gin.Context) {
		a.Login(c)
	})

}

func (a *App) Login(c *gin.Context) {
	var lg Login
	err := c.ShouldBindJSON(&lg)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request"})
		a.Log.Info().Msgf("Login failed: [%s]", err.Error())
	} else {

		u := User{Username: lg.Username}
		if a.checkLoginDetails(&lg, &u) != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Username or password incorrect"})
		} else {
			a.Log.Debug().Msg("Login OK; Creating JWT")
			token, err := utils.GenerateToken(u.Username, u.AdminId)
			if err != nil {
				a.Log.Info().Msgf("Error creating JWT; Error [%s]", err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went bang"})
			} else {
				c.JSON(http.StatusOK, gin.H{"token": token})
			}
		}
	}
}
