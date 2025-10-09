package main

import (
	"github.com/cliveyg/poptape-admin/awsutil"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"go.mongodb.org/mongo-driver/mongo"
	"gorm.io/gorm"
)

type App struct {
	Router        *gin.Engine
	DB            *gorm.DB
	Log           *zerolog.Logger
	Mongo         *mongo.Client
	AWS           *awsutil.AWSAdmin
	CommandRunner CommandRunner
}

func (a *App) InitialiseApp() {
	a.Router = gin.Default()
	a.InitialiseMiddleWare()
	a.InitialiseRoutes()
	a.InitialisePostgres()
	a.PopulatePostgresDB()
	a.InitialiseMongo()
	a.InitialiseAWS()
}

func (a *App) Run(port string) {
	a.Log.Info().Msgf("Server running on port [%s]", port)
	a.Log.Fatal().Err(a.Router.Run(port))
}
