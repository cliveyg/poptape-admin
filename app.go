package main

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"os"
)

type App struct {
	Router *gin.Engine
	DB     *gorm.DB
	Log    *zerolog.Logger
}

func (a *App) InitialiseApp() {

	a.Router = gin.Default()
	//a.Router.ContextWithFallback = true
	a.initializeMiddleWare()
	a.initializeRoutes()
	a.InitialiseDatabase()

}

func (a *App) Run(port string) {
	a.Log.Info().Msgf("Server running on port [%s]", port)
	a.Log.Fatal().Err(a.Router.Run(port))
}

func (a *App) InitialiseDatabase() {

	dsn := fmt.Sprintf("user=%s password=%s dbname=%s host=%s port=%s sslmode=disable",
		os.Getenv("DB_USERNAME"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
	)

	var err error
	a.DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		a.Log.Fatal().Err(err)
	} else {
		a.Log.Info().Msg("Connected to db successfully")
		a.MigrateModels()
	}
}

func (a *App) MigrateModels() {

	a.Log.Info().Msg("Migrating models")
	err := a.DB.AutoMigrate(&Users{}, &Roles{}, &UserRoles{}, &Creds{}, &Microservice{}, &APIPaths{})
	if err != nil {
		a.Log.Fatal().Err(err)
	}

	if a.DB.Migrator().HasTable(&Users{}) {
		if err404 := a.DB.First(&Users{}).Error; errors.Is(err404, gorm.ErrRecordNotFound) {
			// no records found so we need to insert superadmin
			a.Log.Info().Msg("No users found. Inserting first user")
			err = a.CreateFirstUser()
			if err != nil {
				a.Log.Fatal().Err(err)
			}
		} else {
			a.Log.Info().Msg("[Users] table already populated")
		}
	} else {
		a.Log.Fatal().Msg("[Users] table not found")
	}

	a.Log.Info().Msg("Models migrated successfully")
}
