package main

import (
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"gorm.io/gorm"
)

type App struct {
	Router *gin.Engine
	DB     *gorm.DB
	Log    *zerolog.Logger
}

func (a *App) InitialiseApp() {
	a.Router = gin.Default()
	a.initializeMiddleWare()
	a.initializeRoutes()
	a.InitialiseDatabase()
	a.PopulateDatabase()
}

func (a *App) Run(port string) {
	a.Log.Info().Msgf("Server running on port [%s]", port)
	a.Log.Fatal().Err(a.Router.Run(port))
}
