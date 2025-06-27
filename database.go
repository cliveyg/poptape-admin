package main

import (
	"errors"
	"fmt"
	"github.com/cliveyg/poptape-admin/utils"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"os"
	"time"
)

func (a *App) InitialiseDatabase() {

	// due to postgres docker container not starting
	// up in time even with depends_on we have to keep
	// trying to connect. if after 60 secs we still
	// haven't connected we log fatal and stop
	timeout := 60 * time.Second
	start := time.Now()
	var err error
	x := 1
	for time.Since(start) < timeout {
		a.Log.Info().Msgf("Trying to connect to db...[%d]", x)
		a.DB, err = connectToDB()
		if err == nil {
			break
		}
		a.Log.Error().Err(err)
		time.Sleep(2 * time.Second)
		x++
	}

	if err != nil {
		a.Log.Fatal().Msgf("Failed to connect to the database after %s seconds", timeout)
	}

	a.Log.Info().Msg("Connected to db successfully")
	a.MigrateModels()
}

func connectToDB() (*gorm.DB, error) {

	dsn := fmt.Sprintf("user=%s password=%s dbname=%s host=%s port=%s sslmode=disable",
		os.Getenv("DB_USERNAME"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
	)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	return db, nil
}

func (a *App) MigrateModels() {

	a.Log.Info().Msg("Migrating models")
	err := a.DB.AutoMigrate(&User{}, &Role{}, &UserRole{}, &Cred{}, &Microservice{}, &APIPath{})
	if err != nil {
		a.Log.Fatal().Err(err)
	}
	a.Log.Info().Msg("Models migrated successfully")
}

func (a *App) PopulateDatabase() {

	var err error
	if a.DB.Migrator().HasTable(&User{}) {
		if err404 := a.DB.First(&User{}).Error; errors.Is(err404, gorm.ErrRecordNotFound) {
			a.Log.Info().Msg("No users found. Creating user")
			err = a.CreateFirstUser()
			if err != nil {
				a.Log.Error().Msg("Unable to create first user")
				a.Log.Error().Err(err)
			}
		} else {
			a.Log.Info().Msg("[Users] table already populated")
		}
	} else {
		a.Log.Fatal().Msg("[Users] table not found")
	}

	if a.DB.Migrator().HasTable(&Role{}) {
		if err404 := a.DB.First(&Role{}).Error; errors.Is(err404, gorm.ErrRecordNotFound) {
			a.Log.Info().Msg("No roles found. Creating roles")
			err = a.CreateRoles()
			if err != nil {
				a.Log.Error().Msg("Unable to create roles")
				a.Log.Error().Err(err)
			}
		} else {
			a.Log.Info().Msg("[Roles] table already populated")
		}
	} else {
		a.Log.Fatal().Msg("[Roles] table not found")
	}

	if a.DB.Migrator().HasTable(&UserRole{}) {
		if err404 := a.DB.First(&UserRole{}).Error; errors.Is(err404, gorm.ErrRecordNotFound) {
			a.Log.Info().Msg("No user roles found. Creating user role for first user")
			err = a.CreateUserRoles()
			if err != nil {
				a.Log.Error().Msgf("Unable to create user roles: [%s]", err.Error())
			}
		} else {
			a.Log.Info().Msg("[UserRoles] table already populated")
		}
	} else {
		a.Log.Fatal().Msg("[UserRoles] table not found")
	}

}

func (a *App) CreateFirstUser() error {

	fu, fuExists := os.LookupEnv("FIRSTUSER")
	pw, pwExists := os.LookupEnv("FIRSTPASS")
	if !fuExists || !pwExists {
		return errors.New("first user env vars not present in .env")
	}
	encryptedPW, err := utils.GenerateHashPassword(pw)
	if err != nil {
		return errors.New("unable to encrypt password")
	}

	u := User{
		Username: fu,
		Password: encryptedPW,
	}

	res := a.DB.Create(&u)
	if res.Error != nil {
		return res.Error
	}

	a.Log.Debug().Msgf("User created; AdminId is [%s]", u.AdminId)
	return nil
}

func (a *App) CreateRoles() error {

	roles := []*Role{
		{RoleName: "super"},
		{RoleName: "admin"},
		{RoleName: "aws"},
		{RoleName: "items"},
		{RoleName: "reviews"},
		{RoleName: "messages"},
		{RoleName: "auctionhouse"},
		{RoleName: "apiserver"},
		{RoleName: "categories"},
		{RoleName: "address"},
		{RoleName: "fotos"},
		{RoleName: "authy"},
	}
	res := a.DB.Create(roles)
	if res.Error != nil {
		return res.Error
	}

	a.Log.Info().Msg("Roles created")
	return nil
}

func (a *App) CreateUserRoles() error {

	u := User{}
	res := a.DB.First(&u)
	if res.Error != nil {
		return res.Error
	}

	r := Role{
		RoleName: "super",
	}
	res = a.DB.First(&r)
	if res.Error != nil {
		return res.Error
	}

	ur := UserRole{
		AdminId:  u.AdminId,
		RoleName: r.RoleName,
	}
	res = a.DB.Create(&ur)
	if res.Error != nil {
		return res.Error
	}
	a.Log.Info().Msgf("UserRole created for [%s]", u.Username)
	return nil
}
