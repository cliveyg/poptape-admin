package app

import (
	"github.com/cliveyg/poptape-admin/awsutil"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"go.mongodb.org/mongo-driver/mongo"
	"time"
)

type App struct {
	Router        *gin.Engine
	DB            DBInterface
	Log           *zerolog.Logger
	Mongo         *mongo.Client
	AWS           awsutil.AWSAdminInterface
	CommandRunner CommandRunner
	Hooks         Hooks // see hooks interface
}

func (a *App) InitialiseApp() {
	a.Router = gin.Default()
	a.InitialiseMiddleWare()
	a.InitialiseRoutes()
	a.InitialisePostgres()
	a.PopulatePostgresDB()
	err := a.InitialiseMongo(GetMongoConfig(),
		DefaultClientFactory,
		DefaultSleep,
		time.Now,
		60*time.Second)
	if err != nil {
		a.Log.Fatal().Err(err).Msg("Failed to initialise MongoDB")
	}
	a.InitialiseAWS()
}

func (a *App) Run(port string) {
	a.Log.Info().Msgf("Server running on port [%s]", port)
	a.Log.Fatal().Err(a.Router.Run(port))
}
