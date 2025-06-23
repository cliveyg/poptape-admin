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
	// trying to connect. if after 45 secs we still
	// haven't connected we log fatal and stop
	timeout := 45 * time.Second
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

	s := "Ibrahima Konaté is stalling on signing a new deal at Liverpool"
	a.testEncryptDecrypt(s)

}

func (a *App) testEncryptDecrypt(s string) {
	key := []byte(os.Getenv("SUPERSECRETKEY"))
	nonce := []byte(os.Getenv("SUPERSECRETNONCE"))

	var es string
	var err error
	es, err = utils.Encrypt([]byte(s), key, nonce)
	if err != nil {
		a.Log.Error().Msg(err.Error())
	}
	a.Log.Debug().Msgf("Encrypted string is [%s]", es)
	a.Log.Info().Msg("Attempting to decrypt")

	var ba []byte
	ba, err = utils.Decrypt(es, key, nonce)
	if err != nil {
		a.Log.Error().Msg(err.Error())
	}
	if s == string(ba) {
		a.Log.Debug().Msgf("Decrypted string is same as original")
	} else {
		a.Log.Debug().Msgf("Error in encryption/decryption process")
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

	u := &User{
		Username:  fu,
		Password:  encryptedPW,
		Active:    true,
		Validated: false,
		Created:   time.Now(),
	}

	res := a.DB.Create(u)
	if res.Error != nil {
		return res.Error
	}

	a.Log.Debug().Msgf("User created; AdminId is [%s]", u.AdminId)
	return nil
}

func (a *App) CreateRoles() error {

	roles := []*Role{
		{RoleName: "super", Created: time.Now()},
		{RoleName: "aws", Created: time.Now()},
		{RoleName: "items", Created: time.Now()},
		{RoleName: "reviews", Created: time.Now()},
		{RoleName: "messages", Created: time.Now()},
		{RoleName: "auctionhouse", Created: time.Now()},
		{RoleName: "apiserver", Created: time.Now()},
		{RoleName: "categories", Created: time.Now()},
		{RoleName: "address", Created: time.Now()},
		{RoleName: "fotos", Created: time.Now()},
		{RoleName: "authy", Created: time.Now()},
	}
	res := a.DB.Create(roles)
	if res.Error != nil {
		return res.Error
	}
	a.Log.Info().Msg("Roles created")
	return nil
}
